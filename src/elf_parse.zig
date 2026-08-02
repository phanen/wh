//! ELF file parsing: headers, dynamic section, string tables.
//!
//! Provides both low-level header/section reading and a higher-level
//! `ParsedElf` value that materializes interpreter, section info,
//! dynamic entries, and the `.dynstr` string table.

const std = @import("std");
const builtin = @import("builtin");

pub const ParseError = error{
    NotElf,
    TooSmall,
    UnsupportedFormat,
    InvalidSectionHeader,
    OutOfMemory,
} || std.Io.Reader.Error;

pub const Header = std.elf.Header;

pub const SectionInfo = struct {
    name: []const u8,
    type: u32,
    offset: u64,
    size: u64,
    link: u32,
    flags: u64,
    shdr_offset: u64,
};

pub const DynamicEntry = struct {
    tag: i64,
    val: u64,
};

pub const ParsedElf = struct {
    header: Header,
    interp: ?[]const u8,
    sections: []SectionInfo,
    dynamics: []DynamicEntry,
    dynstr: []const u8,
    data: []const u8,

    pub fn deinit(self: *ParsedElf, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.free(self.sections);
        allocator.free(self.dynamics);
        self.* = undefined;
    }

    pub fn findSection(self: *const ParsedElf, name: []const u8) ?SectionInfo {
        for (self.sections) |s| {
            if (std.mem.eql(u8, s.name, name)) return s;
        }
        return null;
    }

    pub fn getNeeded(self: *const ParsedElf, allocator: std.mem.Allocator) ![]const []const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (list.items) |n| allocator.free(n);
            list.deinit(allocator);
        }
        for (self.dynamics) |d| {
            if (d.tag == 0) break; // DT_NULL terminates the dynamic array
            if (d.tag == std.elf.DT_NEEDED) {
                const n = dynstrLookup(self.dynstr, d.val);
                try list.append(allocator, try allocator.dupe(u8, n));
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    pub fn getRpath(self: *const ParsedElf) ?[]const u8 {
        for (self.dynamics) |d| {
            if (d.tag == std.elf.DT_RPATH) return dynstrLookup(self.dynstr, d.val);
        }
        return null;
    }

    pub fn getRunpath(self: *const ParsedElf) ?[]const u8 {
        for (self.dynamics) |d| {
            if (d.tag == std.elf.DT_RUNPATH) return dynstrLookup(self.dynstr, d.val);
        }
        return null;
    }

    pub fn getSoversion(self: *const ParsedElf) ?[]const u8 {
        for (self.dynamics) |d| {
            if (d.tag == std.elf.DT_SONAME) return dynstrLookup(self.dynstr, d.val);
        }
        return null;
    }
};

/// Maximum file size accepted by `parseFile` / `parseFromBytes`.
pub const max_file_size: usize = 100 * 1024 * 1024;

/// Parse an ELF file from disk. Reads the entire file into memory first.
pub fn parseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ParseError!ParsedElf {
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_size)) catch
        return ParseError.NotElf;
    return parseFromBytes(allocator, data) catch |err| {
        allocator.free(data);
        return err;
    };
}

/// Parse ELF data from an in-memory buffer. Caller transfers ownership of
/// `data` to the returned `ParsedElf` (use `deinit` to free it).
pub fn parseFromBytes(
    allocator: std.mem.Allocator,
    data: []const u8,
) ParseError!ParsedElf {
    if (data.len < @sizeOf(std.elf.Elf64_Ehdr)) return ParseError.TooSmall;
    if (!std.mem.eql(u8, data[0..4], std.elf.MAGIC)) return ParseError.NotElf;

    const ident = data[0..std.elf.EI.NIDENT];
    const is_64 = ident[std.elf.EI.CLASS] == std.elf.ELFCLASS64;
    const endian: std.builtin.Endian = switch (ident[std.elf.EI.DATA]) {
        std.elf.ELFDATA2LSB => .little,
        std.elf.ELFDATA2MSB => .big,
        else => return ParseError.UnsupportedFormat,
    };

    if (!is_64) return ParseError.UnsupportedFormat;

    var hdr_reader: std.Io.Reader = .fixed(data);
    const ehdr = try hdr_reader.takeStruct(std.elf.Elf64_Ehdr, endian);

    const header: Header = .init(ehdr, endian);

    var phdr_iter = header.iterateProgramHeadersBuffer(data);
    var interp: ?[]const u8 = null;
    while (try phdr_iter.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_INTERP) continue;
        const off: usize = @intCast(phdr.p_offset);
        const sz: usize = @intCast(phdr.p_filesz);
        if (off + sz > data.len) continue;
        interp = cstr(data[off .. off + sz]);
    }

    var sh_iter = header.iterateSectionHeadersBuffer(data);
    var raw_shdrs: std.ArrayList(std.elf.Elf64_Shdr) = .empty;
    errdefer raw_shdrs.deinit(allocator);
    while (try sh_iter.next()) |shdr| {
        try raw_shdrs.append(allocator, shdr);
    }
    defer raw_shdrs.deinit(allocator);

    const shstrndx: usize = @intCast(header.shstrndx);
    if (shstrndx >= raw_shdrs.items.len) return ParseError.InvalidSectionHeader;
    const shstr_shdr = raw_shdrs.items[shstrndx];
    const shstr_off: usize = @intCast(shstr_shdr.sh_offset);
    const shstr_sz: usize = @intCast(shstr_shdr.sh_size);
    if (shstr_off + shstr_sz > data.len) return ParseError.InvalidSectionHeader;
    const shstrtab = data[shstr_off .. shstr_off + shstr_sz];

    var sections: std.ArrayList(SectionInfo) = .empty;
    errdefer sections.deinit(allocator);
    var i: usize = 0;
    while (i < raw_shdrs.items.len) : (i += 1) {
        const shdr = raw_shdrs.items[i];
        const name_off: usize = @intCast(shdr.sh_name);
        if (name_off >= shstrtab.len) return ParseError.InvalidSectionHeader;
        const name = cstr(shstrtab[name_off..]);
        try sections.append(allocator, .{
            .name = name,
            .type = shdr.sh_type,
            .offset = shdr.sh_offset,
            .size = shdr.sh_size,
            .link = shdr.sh_link,
            .flags = shdr.sh_flags,
            .shdr_offset = header.shoff + @as(u64, @intCast(i)) * @as(u64, header.shentsize),
        });
    }

    var dyn: ?SectionInfo = null;
    for (sections.items) |s| {
        if (s.type == std.elf.SHT_DYNAMIC) {
            dyn = s;
            break;
        }
    }

    var dynstr: []const u8 = &.{};
    if (dyn) |d| {
        const dyn_link: usize = @intCast(d.link);
        if (dyn_link < raw_shdrs.items.len) {
            const ds = raw_shdrs.items[dyn_link];
            const off: usize = @intCast(ds.sh_offset);
            const sz: usize = @intCast(ds.sh_size);
            if (off + sz <= data.len) {
                dynstr = data[off .. off + sz];
            }
        }
    }

    var dynamics: std.ArrayList(DynamicEntry) = .empty;
    errdefer dynamics.deinit(allocator);
    if (dyn) |d| {
        var d_iter = header.iterateDynamicSectionBuffer(data, d.offset, d.size);
        while (try d_iter.next()) |entry| {
            try dynamics.append(allocator, .{
                .tag = entry.d_tag,
                .val = entry.d_val,
            });
        }
    }

    return ParsedElf{
        .header = header,
        .interp = interp,
        .sections = try sections.toOwnedSlice(allocator),
        .dynamics = try dynamics.toOwnedSlice(allocator),
        .dynstr = dynstr,
        .data = data,
    };
}

fn cstr(s: []const u8) []const u8 {
    const zero = std.mem.indexOfScalar(u8, s, 0) orelse s.len;
    return s[0..zero];
}

fn dynstrLookup(dynstr: []const u8, offset: u64) []const u8 {
    if (offset >= dynstr.len) return "";
    return cstr(dynstr[@intCast(offset)..]);
}

/// Read an entire file using raw POSIX syscalls. Test-only helper that
/// avoids the `std.Io` requirement.
pub fn readFilePosix(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (builtin.os.tag != .linux) return error.UnsupportedOs;
    const linux = std.os.linux;
    const path_z = try std.posix.toPosixPath(path);
    const fd_rc = linux.open(&path_z, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.FileOpenFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const statx_rc = linux.statx(
        fd,
        "",
        linux.AT.EMPTY_PATH,
        .{ .SIZE = true },
        &stx,
    );
    if (linux.errno(statx_rc) != .SUCCESS) return error.StatFailed;
    const size: usize = @intCast(stx.size);

    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    var total: usize = 0;
    while (total < size) {
        const n_rc = linux.read(fd, buf.ptr + total, size - total);
        switch (linux.errno(n_rc)) {
            .SUCCESS => {
                const n: usize = n_rc;
                if (n == 0) break;
                total += n;
            },
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
    return buf[0..total];
}

test "elf_parse: parse /usr/bin/ls" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const data = try readFilePosix(allocator, "/usr/bin/ls");
    var parsed = try parseFromBytes(allocator, data);
    defer parsed.deinit(allocator);

    try std.testing.expect(parsed.header.is_64);
    try std.testing.expect(parsed.header.endian == .little);
    try std.testing.expect(
        parsed.header.type == .EXEC or parsed.header.type == .DYN,
    );
    try std.testing.expect(parsed.header.machine == .X86_64);
    try std.testing.expect(parsed.interp != null);

    const needed = try parsed.getNeeded(allocator);
    defer {
        for (needed) |n| allocator.free(n);
        allocator.free(needed);
    }
    var found_libc = false;
    for (needed) |n| {
        if (std.mem.startsWith(u8, n, "libc")) found_libc = true;
    }
    try std.testing.expect(found_libc);
}

test "elf_parse: find .dynstr and .dynamic sections" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const data = try readFilePosix(allocator, "/usr/bin/ls");
    var parsed = try parseFromBytes(allocator, data);
    defer parsed.deinit(allocator);

    try std.testing.expect(parsed.findSection(".dynstr") != null);
    try std.testing.expect(parsed.findSection(".dynamic") != null);
    try std.testing.expect(parsed.dynstr.len > 0);
}

test "elf_parse: rejects non-ELF" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..14], "this is not EL");
    buf[14] = 'F';
    const result = parseFromBytes(allocator, buf[0..]);
    try std.testing.expectError(ParseError.NotElf, result);
}

test "elf_parse: rejects too-small buffer" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 1, 2, 3 };
    const result = parseFromBytes(allocator, &bytes);
    try std.testing.expectError(ParseError.TooSmall, result);
}

test "elf_parse: cstr helper" {
    var buf1: [16]u8 = undefined;
    @memcpy(buf1[0..5], "hello");
    buf1[5] = 0;
    @memcpy(buf1[6..11], "world");
    try std.testing.expectEqualStrings("hello", cstr(buf1[0..11]));

    var buf2: [8]u8 = undefined;
    @memcpy(buf2[0..5], "plain");
    try std.testing.expectEqualStrings("plain", cstr(buf2[0..5]));

    var buf3: [8]u8 = undefined;
    buf3[0] = 0;
    @memcpy(buf3[1..6], "stuff");
    try std.testing.expectEqualStrings("", cstr(buf3[0..6]));
}