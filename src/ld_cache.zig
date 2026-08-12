//! /etc/ld.so.cache reader.
//!
//! Header layout (glibc dl-cache.h, struct cache_file_new):
//!   [0..17]  magic "glibc-ld.so.cache"
//!   [17..20] version "1.1"
//!   [20..24] nlibs (u32)
//!   [24..28] len_strings (u32)
//!   [28]    flags (u8; low 2 bits = byte order)
//!   [32..36] extension_offset (u32)
//!   [36..48] unused padding
//!
//! Entries are DESCENDING by glibc `_dl_cache_libcmp` (digit-aware
//! comparison), so lookups must use the same ordering.

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

pub const LDCache = struct {
    data: []u8,
    entry_count: u32,
    header_size: usize,
    endian: std.builtin.Endian,

    pub fn load(allocator: std.mem.Allocator, io: std.Io) LoadError!LDCache {
        const data = std.Io.Dir.cwd().readFileAlloc(io, "/etc/ld.so.cache", allocator, .limited(max_size)) catch
            return LoadError.NotACache;
        return try fromBytes(data);
    }

    pub fn fromBytes(data: []u8) LoadError!LDCache {
        if (data.len < header_size) return LoadError.TooSmall;
        if (!std.mem.eql(u8, data[0..magic_len], "glibc-ld.so.cache")) return LoadError.NotACache;
        if (!std.mem.eql(u8, data[magic_len .. magic_len + version_len], "1.1")) return LoadError.UnsupportedVersion;

        const flags = data[magic_len + version_len + 8];
        const endian = detectEndian(flags);
        const nlibs = readU32(data, magic_len + version_len, endian);

        const entries_end = header_size + @as(usize, nlibs) * entry_size;
        if (entries_end > data.len) return LoadError.TooSmall;

        return .{
            .data = data,
            .entry_count = nlibs,
            .header_size = header_size,
            .endian = endian,
        };
    }

    pub fn deinit(self: *LDCache, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }

    pub fn lookup(self: *const LDCache, soname: []const u8) ?[]const u8 {
        // glibc sorts DESCENDING by _dl_cache_libcmp, so the search must
        // use libcmpOrder, not plain byte order (libfoo.so.2 < .so.10).
        var lo: u32 = 0;
        var hi: u32 = self.entry_count;
        while (lo < hi) {
            const mid: u32 = lo + (hi - lo) / 2;
            const entry_off = self.header_size + @as(usize, mid) * entry_size;
            const key_off = readU32(self.data, entry_off + 4, self.endian);
            // Cache is untrusted external data; reject out-of-range offsets.
            if (key_off >= self.data.len) return null;
            const key = cstrAt(self.data, key_off);
            switch (libcmpOrder(key, soname)) {
                .eq => return self.pickBestArch(mid, soname),
                .gt => lo = mid + 1,
                .lt => hi = mid,
            }
        }
        return null;
    }

    fn pickBestArch(self: *const LDCache, mid: u32, soname: []const u8) []const u8 {
        const preferred: u32 = hostArchFlag();

        var first: u32 = mid;
        while (first > 0) {
            const prev = first - 1;
            const key_off = readU32(self.data, self.header_size + @as(usize, prev) * entry_size + 4, self.endian);
            if (!std.mem.eql(u8, cstrAt(self.data, key_off), soname)) break;
            first = prev;
        }

        var last: u32 = mid;
        while (last + 1 < self.entry_count) {
            const next = last + 1;
            const key_off = readU32(self.data, self.header_size + @as(usize, next) * entry_size + 4, self.endian);
            if (!std.mem.eql(u8, cstrAt(self.data, key_off), soname)) break;
            last = next;
        }

        if (first > last or last >= self.entry_count) return "";
        var best_off: u32 = 0;
        var best_score: u8 = 0;
        var idx: u32 = first;
        while (idx <= last) : (idx += 1) {
            const entry_off = self.header_size + @as(usize, idx) * entry_size;
            const flags_raw: u32 = readU32(self.data, entry_off, self.endian);
            const val_off = readU32(self.data, entry_off + 8, self.endian);

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

    pub fn entryAt(self: *const LDCache, index: u32) CacheEntry {
        const entry_off = self.header_size + @as(usize, index) * entry_size;
        const key_off = readU32(self.data, entry_off + 4, self.endian);
        const val_off = readU32(self.data, entry_off + 8, self.endian);
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

/// Resolve the byte order recorded in the cache header. 0 means "native"
/// (the cache was written on this machine), 2 = LSB, 3 = MSB.
fn detectEndian(flags: u8) std.builtin.Endian {
    return switch (@as(u2, @truncate(flags))) {
        2 => .little,
        3 => .big,
        else => builtin.cpu.arch.endian(),
    };
}

fn readU32(data: []const u8, offset: usize, endian: std.builtin.Endian) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], endian);
}

/// Mirrors glibc `_dl_cache_libcmp` (elf/dl-cache.c): digit runs are
/// compared numerically, so libfoo.so.2 sorts before libfoo.so.10.
/// End of string is less than any character. ldconfig sorts the cache
/// with this ordering, so lookups must use it.
fn libcmpOrder(left: []const u8, right: []const u8) std.math.Order {
    var i: usize = 0;
    var j: usize = 0;
    while (i < left.len) {
        const lc = left[i];
        if (lc >= '0' and lc <= '9') {
            if (j < right.len and right[j] >= '0' and right[j] <= '9') {
                var val_a: u64 = 0;
                while (i < left.len and left[i] >= '0' and left[i] <= '9') : (i += 1) {
                    val_a = val_a * 10 + (left[i] - '0');
                }
                var val_b: u64 = 0;
                while (j < right.len and right[j] >= '0' and right[j] <= '9') : (j += 1) {
                    val_b = val_b * 10 + (right[j] - '0');
                }
                if (val_a < val_b) return .lt;
                if (val_a > val_b) return .gt;
            } else {
                // left has a digit where right has a non-digit or is exhausted.
                return .gt;
            }
        } else if (j < right.len and right[j] >= '0' and right[j] <= '9') {
            return .lt;
        } else if (j >= right.len or lc != right[j]) {
            if (j >= right.len) return .gt;
            return if (lc < right[j]) .lt else .gt;
        } else {
            i += 1;
            j += 1;
        }
    }
    if (j < right.len) return .lt;
    return .eq;
}

fn cstrAt(data: []const u8, offset: u32) []const u8 {
    const off: usize = @intCast(offset);
    if (off >= data.len) return "";
    return util.cstr(data[off..]);
}

test "ld_cache: load and lookup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var cache = try LDCache.load(std.testing.allocator, std.testing.io);
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
    var cache = try LDCache.load(std.testing.allocator, std.testing.io);
    defer cache.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?[]const u8, null), cache.lookup("definitely-not-a-real-library.xyz123"));
}

// Every entry must be findable: glibc sorts by libcmpOrder, so a lookup
// keyed on plain byte order would miss digit-padded names (regression test).
test "ld_cache: every cache entry is findable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var cache = try LDCache.load(std.testing.allocator, std.testing.io);
    defer cache.deinit(std.testing.allocator);

    var i: u32 = 0;
    while (i < cache.entry_count) : (i += 1) {
        const entry = cache.entryAt(i);
        const found = cache.lookup(entry.soname);
        try std.testing.expect(found != null);
    }
}

test "ld_cache: libcmpOrder matches glibc numeric ordering" {
    const Order = std.math.Order;
    try std.testing.expectEqual(Order.lt, libcmpOrder("libfoo.so.2", "libfoo.so.10"));
    try std.testing.expectEqual(Order.gt, libcmpOrder("libfoo.so.10", "libfoo.so.2"));
    try std.testing.expectEqual(Order.eq, libcmpOrder("libfoo.so.10", "libfoo.so.010"));
    try std.testing.expectEqual(Order.lt, libcmpOrder("liba.so.1", "libb.so.1"));
    try std.testing.expectEqual(Order.gt, libcmpOrder("libb.so.1", "liba.so.1"));
    try std.testing.expectEqual(Order.lt, libcmpOrder("libfoo.so.1", "libfoo.so.1.extra"));
    // Leading zeros: both numeric values are zero, so compare equal.
    try std.testing.expectEqual(Order.eq, libcmpOrder("libfoo.so.0", "libfoo.so.00"));
}

test "ld_cache: readU32 helper" {
    var buf: [8]u8 = .{ 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(u32, 0x78563412), readU32(&buf, 0, .little));
    try std.testing.expectEqual(@as(u32, 0x12345678), readU32(&buf, 0, .big));
}

test "ld_cache: rejects non-cache data" {
    var buf: [128]u8 = .{0} ** 128;
    @memcpy(buf[0..4], "test");
    const result = LDCache.fromBytes(&buf);
    try std.testing.expectError(LoadError.NotACache, result);
}
