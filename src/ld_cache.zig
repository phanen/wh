//! /etc/ld.so.cache binary search reader.
//!
//! Cache header byte layout:
//!   [0..17]   magic "glibc-ld.so.cache\0"
//!   [18..20]  version "1.1\0"
//!   [21..24]  nlibs (u32)
//!   [25..28]  len_strings (u32)
//!   [29..47]  padding to 48-byte aligned header

const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");

pub const LoadError = error{
    NotACache,
    UnsupportedVersion,
    TooSmall,
    OutOfMemory,
};

const header_size: usize = 48;
const entry_size: usize = 24;
const magic_len: usize = 17;
const version_len: usize = 3;

pub const CacheEntry = struct {
    soname: []const u8,
    path: []const u8,
};

pub const LdCache = struct {
    data: []u8,
    entry_count: u32,
    header_size: usize,
    needs_swap: bool,

    pub fn load(allocator: std.mem.Allocator, io: std.Io) LoadError!LdCache {
        const data = std.Io.Dir.cwd().readFileAlloc(io, "/etc/ld.so.cache", allocator, .limited(max_size)) catch
            return LoadError.NotACache;
        return try fromBytes(data);
    }

    pub fn fromBytes(data: []u8) LoadError!LdCache {
        if (data.len < header_size) return LoadError.TooSmall;
        if (!std.mem.eql(u8, data[0..magic_len], "glibc-ld.so.cache")) return LoadError.NotACache;
        if (!std.mem.eql(u8, data[magic_len .. magic_len + version_len], "1.1")) return LoadError.UnsupportedVersion;

        const flags = data[magic_len + version_len + 8];
        const need_swap = detectEndian(flags);
        const nlibs = readU32(data, magic_len + version_len, need_swap);

        const entries_end = header_size + @as(usize, nlibs) * entry_size;
        if (entries_end > data.len) return LoadError.TooSmall;

        return .{
            .data = data,
            .entry_count = nlibs,
            .header_size = header_size,
            .needs_swap = need_swap,
        };
    }

    pub fn deinit(self: *LdCache, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }

    pub fn lookup(self: *const LdCache, soname: []const u8) ?[]const u8 {
        // Entries are sorted DESCENDING by SONAME (glibc uses reversed _dl_cache_libcmp).
        var lo: u32 = 0;
        var hi: u32 = self.entry_count;
        while (lo < hi) {
            const mid: u32 = lo + (hi - lo) / 2;
            const entry_off = self.header_size + @as(usize, mid) * entry_size;
            const key_off = readU32(self.data, entry_off + 4, self.needs_swap);
            const key = cstrAt(self.data, key_off);
            const ord = std.mem.order(u8, key, soname);
            if (ord == .eq) {
                // Multiple entries may share the same SONAME with different architecture flags.
                return self.pickBestArch(mid, soname);
            }
            if (ord == .gt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return null;
    }

    fn pickBestArch(self: *const LdCache, mid: u32, soname: []const u8) []const u8 {
        const preferred: u32 = hostArchFlag();

        var first: u32 = mid;
        while (first > 0) {
            const prev = first - 1;
            const key_off = readU32(self.data, self.header_size + @as(usize, prev) * entry_size + 4, self.needs_swap);
            if (!std.mem.eql(u8, cstrAt(self.data, key_off), soname)) break;
            first = prev;
        }

        var last: u32 = mid;
        while (last + 1 < self.entry_count) {
            const next = last + 1;
            const key_off = readU32(self.data, self.header_size + @as(usize, next) * entry_size + 4, self.needs_swap);
            if (!std.mem.eql(u8, cstrAt(self.data, key_off), soname)) break;
            last = next;
        }

        var best_off: u32 = 0;
        var best_score: u8 = 0;
        var idx: u32 = first;
        while (idx <= last) : (idx += 1) {
            const entry_off = self.header_size + @as(usize, idx) * entry_size;
            const flags_raw: u32 = readU32(self.data, entry_off, self.needs_swap);
            const val_off = readU32(self.data, entry_off + 8, self.needs_swap);

            var score: u8 = 1;
            if (preferred != 0 and (flags_raw & preferred) != 0) {
                score = 3;
            } else if ((flags_raw & FLAG_TYPE_MASK) == FLAG_ELF_LIBC6) {
                score = 2;
            }

            if (score > best_score) {
                best_score = score;
                best_off = val_off;
            }
        }

        return cstrAt(self.data, best_off);
    }

    pub fn entryAt(self: *const LdCache, index: u32) CacheEntry {
        const entry_off = self.header_size + @as(usize, index) * entry_size;
        const key_off = readU32(self.data, entry_off + 4, self.needs_swap);
        const val_off = readU32(self.data, entry_off + 8, self.needs_swap);
        return .{
            .soname = cstrAt(self.data, key_off),
            .path = cstrAt(self.data, val_off),
        };
    }
};

const max_size: usize = 32 * 1024 * 1024;

// glibc ld.so.cache architecture flags (from dl-cache.h).
const FLAG_TYPE_MASK: u32 = 0x00ff;
const FLAG_ELF_LIBC6: u32 = 0x0003;
const FLAG_X8664_LIB64: u32 = 0x0300;
const FLAG_AARCH64_LIB64: u32 = 0x0a00;

fn hostArchFlag() u32 {
    return switch (builtin.cpu.arch) {
        .x86_64 => FLAG_X8664_LIB64,
        .aarch64 => FLAG_AARCH64_LIB64,
        else => 0,
    };
}

fn detectEndian(flags: u8) bool {
    const endian: u2 = @truncate(flags);
    const want: u2 = switch (builtin.cpu.arch.endian()) {
        .little => 2,
        .big => 3,
    };
    return endian != 0 and endian != want;
}

fn readU32(data: []const u8, offset: usize, swap: bool) u32 {
    const raw: u32 = @as(*align(1) const u32, @ptrCast(data[offset..].ptr)).*;
    return if (swap) @byteSwap(raw) else raw;
}

fn cstrAt(data: []const u8, offset: u32) []const u8 {
    const off: usize = @intCast(offset);
    if (off >= data.len) return "";
    return util.cstr(data[off..]);
}

test "ld_cache: load and lookup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var cache = try LdCache.load(std.testing.allocator, std.testing.io);
    defer cache.deinit(std.testing.allocator);

    try std.testing.expect(cache.entry_count > 0);

    if (cache.lookup("libc.so.6")) |path| {
        try std.testing.expect(path.len > 0);
        try std.testing.expect(std.fs.path.isAbsolute(path));
    } else {
        std.log.warn("libc.so.6 not in cache", .{});
    }
}

test "ld_cache: missing soname returns null" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var cache = try LdCache.load(std.testing.allocator, std.testing.io);
    defer cache.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?[]const u8, null), cache.lookup("definitely-not-a-real-library.xyz123"));
}

test "ld_cache: readU32 helper" {
    var buf: [8]u8 = .{ 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(u32, 0x78563412), readU32(&buf, 0, false));
    try std.testing.expectEqual(@as(u32, 0x12345678), readU32(&buf, 0, true));
}

test "ld_cache: rejects non-cache data" {
    var buf: [128]u8 = .{0} ** 128;
    @memcpy(buf[0..4], "test");
    const result = LdCache.fromBytes(&buf);
    try std.testing.expectError(LoadError.NotACache, result);
}