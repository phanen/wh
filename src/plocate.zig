const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");

const c = struct {
    extern fn ZSTD_createDCtx() ?*anyopaque;
    extern fn ZSTD_freeDCtx(ctx: ?*anyopaque) usize;
    extern fn ZSTD_createDDict(dict: [*]const u8, dict_size: usize) ?*anyopaque;
    extern fn ZSTD_freeDDict(ddict: ?*anyopaque) usize;

    extern fn ZSTD_decompress_usingDDict(
        dctx: *anyopaque,
        dst: [*]u8,
        dst_capacity: usize,
        src: [*]const u8,
        src_size: usize,
        ddict: *const anyopaque,
    ) usize;

    extern fn ZSTD_decompressDCtx(
        dctx: *anyopaque,
        dst: [*]u8,
        dst_capacity: usize,
        src: [*]const u8,
        src_size: usize,
    ) usize;

    extern fn ZSTD_getFrameContentSize(src: [*]const u8, src_size: usize) u64;
    extern fn ZSTD_isError(code: usize) u32;
    extern fn ZSTD_getErrorName(code: usize) [*:0]const u8;
};

const ZSTD_CONTENTSIZE_ERROR: u64 = std.math.maxInt(u64) - 1;
const ZSTD_CONTENTSIZE_UNKNOWN: u64 = std.math.maxInt(u64);

const HEADER_SIZE: usize = 112;
const TRIGRAM_ENTRY_SIZE: usize = 16; // struct { trgm: u32, num_docids: u32, offset: u64 }
const PACFILES_SUFFIX: []const u8 = ".pacfiles";
const sync_dir: []const u8 = "/var/lib/pacman/sync";

pub const PacfilesMatch = struct {
    pkgname: []const u8,
    version: []const u8,
    repo: []const u8,
    filepath: []const u8,
};

const Header = extern struct {
    magic: [8]u8,
    version: u32,
    hashtable_size: u32,
    extra_ht_slots: u32,
    num_docids: u32,
    hash_table_offset_bytes: u64,
    filename_index_offset_bytes: u64,
    max_version: u32,
    zstd_dictionary_length_bytes: u32,
    zstd_dictionary_offset_bytes: u64,

    comptime {
        std.debug.assert(@sizeOf(Header) == 56);
    }
};

const EntryParts = struct {
    pkgname: []const u8,
    version: []const u8,
    path: []const u8,
};

fn hashTrigram(trgm: u32, ht_size: u32) u32 {
    var crc = trgm;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const bit = (crc & 0x80000000) != 0;
        crc <<= 1;
        if (bit) crc ^= 0x1edc6f41;
    }
    return crc % ht_size;
}

fn targetTrigramsExist(hdr: *align(1) const Header, file_reader: anytype, target: []const u8) !bool {
    if (target.len < 3) return true;
    var i: usize = 0;
    while (i <= target.len - 3) : (i += 1) {
        const trgm: u32 = @as(u32, target[i]) |
            (@as(u32, target[i + 1]) << 8) |
            (@as(u32, target[i + 2]) << 16);
        if (trgm == 0) continue;
        const found = try trigramPresent(hdr, file_reader, trgm);
        if (!found) return false;
    }
    return true;
}

fn trigramPresent(hdr: *align(1) const Header, file_reader: anytype, trgm: u32) !bool {
    const bucket = hashTrigram(trgm, hdr.hashtable_size);
    const slots: u32 = hdr.extra_ht_slots + 1;
    var s: u32 = 0;
    while (s < slots) : (s += 1) {
        const slot = (bucket + s) % hdr.hashtable_size;
        const off = hdr.hash_table_offset_bytes + @as(u64, slot) * TRIGRAM_ENTRY_SIZE;
        try file_reader.seekTo(off);
        var buf: [4]u8 = undefined;
        try file_reader.interface.readSliceAll(&buf);
        const v: u32 = @as(u32, buf[0]) |
            (@as(u32, buf[1]) << 8) |
            (@as(u32, buf[2]) << 16) |
            (@as(u32, buf[3]) << 24);
        if (v == trgm) return true;
        if (v == 0) return false;
    }
    return false;
}

pub fn dbsExist(io: std.Io) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, sync_dir, .{ .iterate = true }) catch
        return false;
    defer dir.close(io);

    var iter = dir.iterate();
    while (iter.next(io) catch return false) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.name, PACFILES_SUFFIX)) return true;
    }
    return false;
}

pub fn search(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
) ![]PacfilesMatch {
    var results: std.ArrayList(PacfilesMatch) = .empty;
    errdefer freeMatches(results.items, allocator);

    var dir = std.Io.Dir.openDirAbsolute(io, sync_dir, .{ .iterate = true }) catch
        return try results.toOwnedSlice(allocator);
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, PACFILES_SUFFIX)) continue;

        const repo_name = entry.name[0 .. entry.name.len - PACFILES_SUFFIX.len];

        const db_matches = searchOneDb(allocator, io, entry.name, target, repo_name) catch |err| {
            std.log.warn("plocate: searchOneDb({s}) failed: {s}", .{
                entry.name,
                @errorName(err),
            });
            continue;
        };
        for (db_matches) |m| {
            results.append(allocator, m) catch |err| {
                freeMatches(db_matches, allocator);
                return err;
            };
        }
        allocator.free(db_matches);
    }

    return try results.toOwnedSlice(allocator);
}

pub fn freeMatches(matches: []PacfilesMatch, allocator: std.mem.Allocator) void {
    for (matches) |m| {
        freeMatch(m, allocator);
    }
    allocator.free(matches);
}

fn freeMatch(match: PacfilesMatch, allocator: std.mem.Allocator) void {
    allocator.free(match.pkgname);
    allocator.free(match.version);
    allocator.free(match.repo);
    allocator.free(match.filepath);
}

fn searchOneDb(
    allocator: std.mem.Allocator,
    io: std.Io,
    db_filename: []const u8,
    target: []const u8,
    repo_name: []const u8,
) ![]PacfilesMatch {
    const db_path = try std.fs.path.join(allocator, &[_][]const u8{ sync_dir, db_filename });
    defer allocator.free(db_path);

    var file = std.Io.Dir.openFileAbsolute(io, db_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return try allocator.alloc(PacfilesMatch, 0),
        else => return err,
    };
    defer file.close(io);

    var read_buf: [16 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);

    var header_buf: [HEADER_SIZE]u8 = undefined;
    try file_reader.interface.readSliceAll(&header_buf);

    const hdr: *align(1) const Header = @ptrCast(&header_buf);
    if (!std.mem.eql(u8, &hdr.magic, "\x00plocate")) return try allocator.alloc(PacfilesMatch, 0);
    if (hdr.version != 0 and hdr.version != 1) return try allocator.alloc(PacfilesMatch, 0);

    if (!(try targetTrigramsExist(hdr, &file_reader, target))) return try allocator.alloc(PacfilesMatch, 0);

    const num_docids = hdr.num_docids;
    const dict_len: usize = @intCast(hdr.zstd_dictionary_length_bytes);
    const dict_off: u64 = hdr.zstd_dictionary_offset_bytes;
    const fname_index_off: u64 = hdr.filename_index_offset_bytes;

    var ddict: ?*anyopaque = null;
    defer if (ddict) |ptr| {
        _ = c.ZSTD_freeDDict(ptr);
    };

    if (dict_len > 0) {
        try file_reader.seekTo(dict_off);
        const dict_buf = try allocator.alloc(u8, dict_len);
        defer allocator.free(dict_buf);
        try file_reader.interface.readSliceAll(dict_buf);
        ddict = c.ZSTD_createDDict(dict_buf.ptr, dict_len) orelse return error.ZstdDictFailed;
    }

    const index_count = num_docids + 1;
    const index_buf = try allocator.alloc(u64, index_count);
    defer allocator.free(index_buf);
    try file_reader.seekTo(fname_index_off);
    try file_reader.interface.readSliceAll(std.mem.sliceAsBytes(index_buf));

    const dctx = c.ZSTD_createDCtx() orelse return error.ZstdCtxFailed;
    defer _ = c.ZSTD_freeDCtx(dctx);

    var block_buf: std.ArrayList(u8) = .empty;
    defer block_buf.deinit(allocator);

    var results: std.ArrayList(PacfilesMatch) = .empty;
    errdefer freeMatches(results.items, allocator);

    var i: u32 = 0;
    while (i < num_docids) : (i += 1) {
        const comp_off = index_buf[i];
        const comp_end = index_buf[i + 1];
        if (comp_end < comp_off) return error.CorruptIndex;
        const comp_size: usize = @intCast(comp_end - comp_off);

        try file_reader.seekTo(comp_off);

        block_buf.clearRetainingCapacity();
        try block_buf.resize(allocator, comp_size);
        try file_reader.interface.readSliceAll(block_buf.items);

        const frame_size = c.ZSTD_getFrameContentSize(block_buf.items.ptr, comp_size);
        if (frame_size == ZSTD_CONTENTSIZE_ERROR or frame_size == ZSTD_CONTENTSIZE_UNKNOWN) {
            std.log.warn("plocate: unknown frame content size at offset {x}", .{comp_off});
            continue;
        }
        const out_size: usize = @intCast(frame_size);

        const out_buf = try allocator.alloc(u8, out_size);
        defer allocator.free(out_buf);

        const written = if (ddict) |d|
            c.ZSTD_decompress_usingDDict(dctx, out_buf.ptr, out_size, block_buf.items.ptr, comp_size, d)
        else
            c.ZSTD_decompressDCtx(dctx, out_buf.ptr, out_size, block_buf.items.ptr, comp_size);

        if (c.ZSTD_isError(written) != 0) {
            std.log.warn("plocate: zstd error: {s}", .{c.ZSTD_getErrorName(written)});
            continue;
        }
        const produced: usize = @intCast(written);
        if (produced != out_size) {
            std.log.warn("plocate: size mismatch {d} != {d}", .{ produced, out_size });
            continue;
        }

        if (scanBlock(allocator, repo_name, out_buf, target)) |m| {
            defer allocator.free(m);
            try results.appendSlice(allocator, m);
        }
    }

    return try results.toOwnedSlice(allocator);
}

fn scanBlock(
    allocator: std.mem.Allocator,
    repo_name: []const u8,
    out_buf: []const u8,
    target: []const u8,
) ?[]PacfilesMatch {
    var found: std.ArrayList(PacfilesMatch) = .empty;
    errdefer freeMatches(found.items, allocator);

    const bare = std.mem.indexOfScalar(u8, target, '/') == null;
    var it = std.mem.splitScalar(u8, out_buf, 0);
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        const parts = parseEntry(entry) orelse continue;
        if (std.mem.eql(u8, parts.path, target)) {
            const m = buildMatch(allocator, repo_name, parts.pkgname, parts.version, parts.path) orelse continue;
            found.append(allocator, m) catch {
                freeMatch(m, allocator);
                continue;
            };
            continue;
        }
        if (bare and util.pathBaseMatches(parts.path, target)) {
            const m = buildMatch(allocator, repo_name, parts.pkgname, parts.version, parts.path) orelse continue;
            found.append(allocator, m) catch {
                freeMatch(m, allocator);
            };
        }
    }

    if (found.items.len == 0) {
        found.deinit(allocator);
        return null;
    }
    return found.toOwnedSlice(allocator) catch null;
}

fn buildMatch(
    allocator: std.mem.Allocator,
    repo: []const u8,
    pkgname: []const u8,
    version: []const u8,
    filepath: []const u8,
) ?PacfilesMatch {
    const pkgname_dup = allocator.dupe(u8, pkgname) catch return null;
    errdefer allocator.free(pkgname_dup);
    const version_dup = allocator.dupe(u8, version) catch return null;
    errdefer allocator.free(version_dup);
    const repo_dup = allocator.dupe(u8, repo) catch return null;
    errdefer allocator.free(repo_dup);
    const filepath_dup = allocator.dupe(u8, filepath) catch return null;
    return .{
        .pkgname = pkgname_dup,
        .version = version_dup,
        .repo = repo_dup,
        .filepath = filepath_dup,
    };
}

fn parseEntry(entry: []const u8) ?EntryParts {
    const slash = std.mem.indexOfScalar(u8, entry, '/') orelse return null;
    const path = entry[slash + 1 ..];
    const prefix = entry[0..slash];

    var boundaries: [2]usize = .{ 0, 0 };
    var found: usize = 0;
    var i: usize = prefix.len;
    while (i > 0 and found < 2) {
        i -= 1;
        if (prefix[i] == '-' and i + 1 < prefix.len and std.ascii.isDigit(prefix[i + 1])) {
            boundaries[found] = i;
            found += 1;
        }
    }

    if (found >= 2) {
        const split = boundaries[1]; // leftmost: pkgver boundary
        return .{
            .pkgname = prefix[0..split],
            .version = prefix[split + 1 ..],
            .path = path,
        };
    }
    if (found == 1) {
        return .{
            .pkgname = prefix[0..boundaries[0]],
            .version = prefix[boundaries[0] + 1 ..],
            .path = path,
        };
    }
    return .{ .pkgname = prefix, .version = "", .path = path };
}

test "plocate: parseEntry splits version boundary" {
    {
        const p = parseEntry("coreutils-9.5-1/usr/bin/ls").?;
        try std.testing.expectEqualStrings("coreutils", p.pkgname);
        try std.testing.expectEqualStrings("9.5-1", p.version);
        try std.testing.expectEqualStrings("usr/bin/ls", p.path);
    }
    {
        const p = parseEntry("glibc-2.42-3/lib/libc.so.6").?;
        try std.testing.expectEqualStrings("glibc", p.pkgname);
        try std.testing.expectEqualStrings("2.42-3", p.version);
        try std.testing.expectEqualStrings("lib/libc.so.6", p.path);
    }
    // Epoch:pkgver-pkgrel (e.g. blender 17:5.2.0-2)
    {
        const p = parseEntry("blender-17:5.2.0-2/usr/bin/blender").?;
        try std.testing.expectEqualStrings("blender", p.pkgname);
        try std.testing.expectEqualStrings("17:5.2.0-2", p.version);
        try std.testing.expectEqualStrings("usr/bin/blender", p.path);
    }
}

test "plocate: parseEntry handles pkgname with dash" {
    const p = parseEntry("linux-lts-6.18.41-1/usr/lib/modules").?;
    try std.testing.expectEqualStrings("linux-lts", p.pkgname);
    try std.testing.expectEqualStrings("6.18.41-1", p.version);
}

test "plocate: parseEntry handles pkgname without dash" {
    const p = parseEntry("singlepkg-1.0-1/etc/conf").?;
    try std.testing.expectEqualStrings("singlepkg", p.pkgname);
    try std.testing.expectEqualStrings("1.0-1", p.version);
}

test "plocate: parseEntry rejects missing slash" {
    try std.testing.expect(parseEntry("noslash") == null);
}

test "plocate: header struct has expected size" {
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Header));
}

test "plocate: search core.pacfiles for ls" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const results = try search(allocator, std.testing.io, "usr/bin/ls");
    defer freeMatches(results, allocator);
    if (results.len > 0) {
        // The heuristic keeps pkgname-pkgver together; just ensure something
        // referencing coreutils turned up.
        try std.testing.expect(std.mem.indexOf(u8, results[0].pkgname, "coreutils") != null);
        try std.testing.expect(results[0].repo.len > 0);
    }
}