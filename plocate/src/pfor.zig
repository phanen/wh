//! PForDelta posting-list decoder (ported from deps/plocate/turbopfor.cpp).
//!
//! The on-disk format encodes the docids of a posting list as follows:
//!   - The first docid is stored via read_baseval (PrefixVarint-like).
//!   - The remaining docids are stored in blocks of 128 values. Each value
//!     in a block is a delta from the previous value (delta[i] = v[i] -
//!     v[i-1] - 1). The block starts with a 1-byte header whose top 2 bits
//!     select the block type and whose low 6 bits give the bit width.
//!
//! Block types:
//!   0 (FOR)         : plain frame-of-reference, deltas packed at bit_width
//!                     bits each. Interleaved variant stores the bits in 4
//!                     streams, a layout the C++ reference decodes with SSE2.
//!   1 (PFOR_VB)     : like FOR but values wider than bit_width become
//!                     variable-byte-encoded exceptions.
//!   2 (PFOR_BITMAP) : like FOR but exceptions are selected by a bitmap and
//!                     stored contiguously at exception_bit_width bits each.
//!   3 (CONSTANT)    : a single delta value repeated for the whole block.
//!
//! Interleaved (4-stream) variants are only used for full 128-value blocks;
//! this port decodes them scalar-ly. The decoder reads u32 words and may look
//! up to 16 bytes past the end of the encoded buffer; callers must guarantee
//! that much padding.

const std = @import("std");

// On-disk plocate header types and constants, exposed here so the test
// fixtures below stand alone without importing plocate.zig.
pub const HEADER_SIZE: usize = 112;
pub const PACLOCATE_MAGIC: [8]u8 = .{ 0, 'p', 'l', 'o', 'c', 'a', 't', 'e' };

pub const Header = extern struct {
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

pub const TrigramEntry = extern struct {
    trgm: u32,
    num_docids: u32,
    offset: u64,

    comptime {
        std.debug.assert(@sizeOf(TrigramEntry) == 16);
    }
};

pub const Docid = u32;

const BLOCK_SIZE: u32 = 128;

pub const BlockType = enum(u2) {
    FOR = 0,
    PFOR_VB = 1,
    PFOR_BITMAP = 2,
    CONSTANT = 3,
};

fn divRoundUp(val: u32, div: u32) u32 {
    return (val + div - 1) / div;
}

fn bytesForPackedBits(num: u32, bit_width: u32) u32 {
    return divRoundUp(num * bit_width, 8);
}

fn maskForBits(bit_width: u32) u32 {
    if (bit_width == 0) return 0;
    if (bit_width >= 32) return 0xFFFFFFFF;
    return (@as(u32, 1) << @intCast(bit_width)) - 1;
}

fn readBaseval(data: []const u8, out: *Docid) error{PforBasevalOverflow}!usize {
    const b0 = data[0];
    if (b0 < 128) {
        out.* = b0;
        return 1;
    } else if (b0 < 192) {
        out.* = ((@as(u32, b0) << 8) | @as(u32, data[1])) & 0x3fff;
        return 2;
    } else if (b0 < 224) {
        out.* = ((@as(u32, b0) << 16) |
            (@as(u32, data[2]) << 8) |
            @as(u32, data[1])) & 0x1fffff;
        return 3;
    } else if (b0 < 240) {
        out.* = ((@as(u32, b0) << 24) |
            (@as(u32, data[1]) << 16) |
            (@as(u32, data[2]) << 8) |
            @as(u32, data[3])) & 0xffffff;
        return 4;
    }
    return error.PforBasevalOverflow;
}

fn readVb(data: [*]const u8, out: *Docid) error{PforVbOverflow}!usize {
    const b0 = data[0];
    if (b0 <= 176) {
        out.* = b0;
        return 1;
    } else if (b0 <= 240) {
        out.* = ((@as(u32, b0 -% 177) << 8) | @as(u32, data[1])) +% 177;
        return 2;
    } else if (b0 <= 248) {
        out.* = ((@as(u32, b0 -% 241) << 16) | @as(u32, std.mem.readInt(u16, (data + 1)[0..2], .little))) +% 16561;
        return 3;
    } else if (b0 == 249) {
        out.* = @as(u32, data[1]) |
            (@as(u32, data[2]) << 8) |
            (@as(u32, data[3]) << 16);
        return 4;
    } else if (b0 == 250) {
        out.* = std.mem.readInt(u32, (data + 1)[0..4], .little);
        return 5;
    }
    return error.PforVbOverflow;
}

const BitReader = struct {
    data: [*]const u8,
    bits: u32,
    mask: u32,
    bits_used: u32 = 0,

    fn init(data: [*]const u8, bits: u32) BitReader {
        return .{
            .data = data,
            .bits = bits,
            .mask = maskForBits(bits),
        };
    }

    // Caller must ensure 4 bytes of readable space after the current data.
    fn read(self: *BitReader) u32 {
        const v = std.mem.readInt(u32, self.data[0..4], .little);
        const shift: u5 = @intCast(self.bits_used);
        const val = (v >> shift) & self.mask;
        self.bits_used += self.bits;
        self.data += self.bits_used / 8;
        self.bits_used %= 8;
        return val;
    }
};

const InterleavedBitReader = struct {
    data: [*]const u8,
    bits: u32,
    mask: u32,
    stride: usize,
    bits_used: u32 = 0,

    fn init(num_streams: u32, data: [*]const u8, bits: u32) InterleavedBitReader {
        return .{
            .data = data,
            .bits = bits,
            .mask = maskForBits(bits),
            .stride = @as(usize, num_streams) * 4,
        };
    }

    // Caller must ensure enough padding after the current data. With 4
    // streams the worst case straddles two adjacent u32 lanes, so 8 bytes
    // of contiguous readable memory past the current lane is sufficient.
    fn read(self: *InterleavedBitReader) u32 {
        var val: u32 = undefined;
        const shift: u5 = @intCast(self.bits_used);
        if (self.bits_used + self.bits > 32) {
            // bits_used is in [1, 32), so the shift amount is in (0, 31].
            const second_shift: u5 = @intCast(32 - self.bits_used);
            val = (std.mem.readInt(u32, self.data[0..4], .little) >> shift) |
                (std.mem.readInt(u32, (self.data + self.stride)[0..4], .little) << second_shift);
        } else {
            val = std.mem.readInt(u32, self.data[0..4], .little) >> shift;
        }
        self.bits_used += self.bits;
        self.data += self.stride * @as(usize, @intCast(self.bits_used / 32));
        self.bits_used %= 32;
        return val & self.mask;
    }
};

fn decodeConstant(data: [*]const u8, num: u32, out: [*]Docid, prev_val_in: Docid) [*]const u8 {
    const bit_width = data[0] & 0x3f;
    const in_ptr = data + 1;
    var val = std.mem.readInt(u32, in_ptr[0..4], .little);
    if (bit_width < 32) val &= maskForBits(bit_width);

    var prev_val = prev_val_in;
    var i: u32 = 0;
    while (i < num) : (i += 1) {
        prev_val +%= val;
        prev_val +%= 1;
        out[i] = prev_val;
    }
    return in_ptr + divRoundUp(bit_width, 8);
}

fn decodeFor(data: [*]const u8, num: u32, out: [*]Docid, prev_val_in: Docid) [*]const u8 {
    const bit_width = data[0] & 0x3f;
    const in_ptr = data + 1;

    var prev_val = prev_val_in;
    var bs = BitReader.init(in_ptr, bit_width);
    var i: u32 = 0;
    while (i < num) : (i += 1) {
        prev_val +%= bs.read();
        prev_val +%= 1;
        out[i] = prev_val;
    }
    return in_ptr + bytesForPackedBits(num, bit_width);
}

fn decodeForInterleaved(data: [*]const u8, out: [*]Docid, prev_val_in: Docid) [*]const u8 {
    const bit_width = data[0] & 0x3f;
    const in_ptr = data + 1;

    var bs0 = InterleavedBitReader.init(4, in_ptr + 0 * 4, bit_width);
    var bs1 = InterleavedBitReader.init(4, in_ptr + 1 * 4, bit_width);
    var bs2 = InterleavedBitReader.init(4, in_ptr + 2 * 4, bit_width);
    var bs3 = InterleavedBitReader.init(4, in_ptr + 3 * 4, bit_width);

    var i: u32 = 0;
    while (i < BLOCK_SIZE) : (i += 4) {
        out[i + 0] = bs0.read();
        out[i + 1] = bs1.read();
        out[i + 2] = bs2.read();
        out[i + 3] = bs3.read();
    }

    var prev_val = prev_val_in;
    var j: u32 = 0;
    while (j < BLOCK_SIZE) : (j += 1) {
        prev_val +%= out[j];
        prev_val +%= 1;
        out[j] = prev_val;
    }
    return in_ptr + bytesForPackedBits(BLOCK_SIZE, bit_width);
}

fn decodePforBitmapExceptions(data: [*]const u8, num: u32, out: [*]Docid) [*]const u8 {
    const exception_bit_width = data[0];
    const in_ptr = data + 1;

    const bitmap_len: usize = divRoundUp(num, 8);
    var num_exceptions: u32 = 0;

    var bs = BitReader.init(in_ptr + bitmap_len, exception_bit_width);
    var bitmap_ptr: [*]const u8 = in_ptr;

    var i: u32 = 0;
    while (i < num) {
        const remaining = num - i;
        var exceptions = std.mem.readInt(u64, bitmap_ptr[0..8], .little);
        bitmap_ptr += 8;
        if (remaining < 64) {
            exceptions &= (@as(u64, 1) << @intCast(remaining)) -% 1;
        }
        while (exceptions != 0) {
            const bit: u32 = @intCast(@ctz(exceptions));
            const idx: u32 = bit + i;
            out[idx] = bs.read();
            exceptions &= exceptions - 1;
            num_exceptions += 1;
        }
        i += 64;
    }

    return in_ptr + bitmap_len + bytesForPackedBits(num_exceptions, exception_bit_width);
}

fn decodePforBitmap(data: [*]const u8, num: u32, out: [*]Docid, prev_val_in: Docid) [*]const u8 {
    var k: u32 = 0;
    while (k < num) : (k += 1) out[k] = 0;

    const bit_width = data[0] & 0x3f;
    const in_ptr = data + 1;

    const after_exc = decodePforBitmapExceptions(in_ptr, num, out);

    var prev_val = prev_val_in;
    var bs = BitReader.init(after_exc, bit_width);
    var i: u32 = 0;
    while (i < num) : (i += 1) {
        const high = if (bit_width == 32) 0 else out[i] << @intCast(bit_width);
        prev_val +%= high | bs.read();
        prev_val +%= 1;
        out[i] = prev_val;
    }
    return after_exc + bytesForPackedBits(num, bit_width);
}

fn decodePforBitmapInterleaved(data: [*]const u8, out: [*]Docid, prev_val_in: Docid) [*]const u8 {
    var k: u32 = 0;
    while (k < BLOCK_SIZE) : (k += 4) {
        const p = out[k..];
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
        p[3] = 0;
    }

    const bit_width = data[0] & 0x3f;
    const in_ptr = data + 1;

    const after_exc = decodePforBitmapExceptions(in_ptr, BLOCK_SIZE, out);

    var bs0 = InterleavedBitReader.init(4, after_exc + 0 * 4, bit_width);
    var bs1 = InterleavedBitReader.init(4, after_exc + 1 * 4, bit_width);
    var bs2 = InterleavedBitReader.init(4, after_exc + 2 * 4, bit_width);
    var bs3 = InterleavedBitReader.init(4, after_exc + 3 * 4, bit_width);

    var i: u32 = 0;
    while (i < BLOCK_SIZE) : (i += 4) {
        if (bit_width == 32) {
            out[i + 0] = bs0.read();
            out[i + 1] = bs1.read();
            out[i + 2] = bs2.read();
            out[i + 3] = bs3.read();
        } else {
            const shift: u5 = @intCast(bit_width);
            out[i + 0] = bs0.read() | (out[i + 0] << shift);
            out[i + 1] = bs1.read() | (out[i + 1] << shift);
            out[i + 2] = bs2.read() | (out[i + 2] << shift);
            out[i + 3] = bs3.read() | (out[i + 3] << shift);
        }
    }

    var prev_val = prev_val_in;
    var j: u32 = 0;
    while (j < BLOCK_SIZE) : (j += 1) {
        prev_val +%= out[j];
        prev_val +%= 1;
        out[j] = prev_val;
    }
    return after_exc + bytesForPackedBits(BLOCK_SIZE, bit_width);
}

fn decodePforVb(data: [*]const u8, num: u32, out: [*]Docid, prev_val_in: Docid) error{PforVbOverflow}![*]const u8 {
    const bit_width = data[0] & 0x3f;
    const num_exceptions: u32 = data[1];
    if (num_exceptions > num) return error.PforVbOverflow;
    var in_ptr: [*]const u8 = data + 2;

    var bs = BitReader.init(in_ptr, bit_width);
    var i: u32 = 0;
    while (i < num) : (i += 1) {
        out[i] = bs.read();
    }
    in_ptr += bytesForPackedBits(num, bit_width);

    var exceptions: [BLOCK_SIZE]Docid = undefined;
    if (in_ptr[0] == 255) {
        in_ptr += 1;
        var j: u32 = 0;
        while (j < num_exceptions) : (j += 1) {
            exceptions[j] = std.mem.readInt(u32, in_ptr[0..4], .little);
            in_ptr += 4;
        }
    } else {
        var j: u32 = 0;
        while (j < num_exceptions) : (j += 1) {
            in_ptr += try readVb(in_ptr, &exceptions[j]);
        }
    }

    const shift: u5 = @intCast(bit_width);
    var k: u32 = 0;
    while (k < num_exceptions) : (k += 1) {
        const idx: u32 = in_ptr[0];
        if (idx >= num) return error.PforVbOverflow;
        in_ptr += 1;
        if (bit_width == 32)
            out[idx] = exceptions[k]
        else
            out[idx] |= exceptions[k] << shift;
    }

    var prev_val = prev_val_in;
    var l: u32 = 0;
    while (l < num) : (l += 1) {
        prev_val +%= out[l];
        prev_val +%= 1;
        out[l] = prev_val;
    }
    return in_ptr;
}

fn decodePforVbInterleaved(data: [*]const u8, out: [*]Docid, prev_val_in: Docid) error{PforVbOverflow}![*]const u8 {
    const bit_width = data[0] & 0x3f;
    const num_exceptions: u32 = data[1];
    if (num_exceptions > BLOCK_SIZE) return error.PforVbOverflow;
    var in_ptr: [*]const u8 = data + 2;

    var bs0 = InterleavedBitReader.init(4, in_ptr + 0 * 4, bit_width);
    var bs1 = InterleavedBitReader.init(4, in_ptr + 1 * 4, bit_width);
    var bs2 = InterleavedBitReader.init(4, in_ptr + 2 * 4, bit_width);
    var bs3 = InterleavedBitReader.init(4, in_ptr + 3 * 4, bit_width);

    var i: u32 = 0;
    while (i < BLOCK_SIZE) : (i += 4) {
        out[i + 0] = bs0.read();
        out[i + 1] = bs1.read();
        out[i + 2] = bs2.read();
        out[i + 3] = bs3.read();
    }
    in_ptr += bytesForPackedBits(BLOCK_SIZE, bit_width);

    var exceptions: [BLOCK_SIZE]Docid = undefined;
    if (in_ptr[0] == 255) {
        in_ptr += 1;
        var j: u32 = 0;
        while (j < num_exceptions) : (j += 1) {
            exceptions[j] = std.mem.readInt(u32, in_ptr[0..4], .little);
            in_ptr += 4;
        }
    } else {
        var j: u32 = 0;
        while (j < num_exceptions) : (j += 1) {
            in_ptr += try readVb(in_ptr, &exceptions[j]);
        }
    }

    const shift: u5 = @intCast(bit_width);
    var k: u32 = 0;
    while (k < num_exceptions) : (k += 1) {
        const idx: u32 = in_ptr[0];
        if (idx >= BLOCK_SIZE) return error.PforVbOverflow;
        in_ptr += 1;
        if (bit_width == 32)
            out[idx] = exceptions[k]
        else
            out[idx] |= exceptions[k] << shift;
    }

    var prev_val = prev_val_in;
    var l: u32 = 0;
    while (l < BLOCK_SIZE) : (l += 1) {
        prev_val +%= out[l];
        prev_val +%= 1;
        out[l] = prev_val;
    }
    return in_ptr;
}

fn decodeBlock(
    data: [*]const u8,
    num: u32,
    full_block: bool,
    out: [*]Docid,
    prev_val: Docid,
) error{PforVbOverflow}![*]const u8 {
    if (data[0] & 0x3f > 32) return error.PforVbOverflow; // bit width > 32 is invalid
    const block_type: BlockType = @enumFromInt(data[0] >> 6);
    switch (block_type) {
        .FOR => {
            if (full_block) return decodeForInterleaved(data, out, prev_val);
            return decodeFor(data, num, out, prev_val);
        },
        .PFOR_VB => {
            if (full_block) return try decodePforVbInterleaved(data, out, prev_val);
            return try decodePforVb(data, num, out, prev_val);
        },
        .PFOR_BITMAP => {
            if (full_block) return decodePforBitmapInterleaved(data, out, prev_val);
            return decodePforBitmap(data, num, out, prev_val);
        },
        .CONSTANT => return decodeConstant(data, num, out, prev_val),
    }
}

/// Decode a PForDelta-encoded posting list.
///
/// `data` must point at a valid encoded posting list for `num` docids; it is
/// safe (and necessary) for the slice to have at least 16 bytes of trailing
/// space because the interleaved decoder may read a u32 past the end of the
/// last used byte. Returns an owned slice of length `num`.
pub fn decodePostingList(
    allocator: std.mem.Allocator,
    data: []const u8,
    num: usize,
) ![]Docid {
    if (num == 0) return allocator.alloc(Docid, 0);

    const out = try allocator.alloc(Docid, num);
    errdefer allocator.free(out);

    var p: [*]const u8 = data.ptr;
    var prev_val: Docid = undefined;
    p += try readBaseval(data, &prev_val);
    out[0] = prev_val;

    var out_idx: usize = 1;
    var remaining: usize = num - 1;
    while (remaining > 0) {
        const num_this: u32 = @intCast(@min(remaining, BLOCK_SIZE));
        const full_block = num_this == BLOCK_SIZE;
        const out_ptr: [*]Docid = out[out_idx..].ptr;
        p = try decodeBlock(p, num_this, full_block, out_ptr, prev_val);
        prev_val = out[out_idx + num_this - 1];
        out_idx += num_this;
        remaining -= num_this;
    }

    return out;
}

// ============================================================================
// Test fixtures
// ============================================================================
//
// Shared real-data fixture: a small posting list for a given block type
// loaded from /var/lib/pacman/sync/core.pacfiles. The buffer is owned by
// the caller and must be freed. `encoded` has 16 bytes of zero padding
// appended after the on-disk bytes so the interleaved decoders may safely
// read past the end.

const PacfileFixture = struct {
    trgm: u32,
    block_type: BlockType,
    num_docids: u32,
    encoded: []u8,
};

// Open a plocate database file and return up to one fixture per block type,
// picked as the smallest posting list (3 <= num_docids <= 30) of each kind so
// the encoded payload is tiny and the test runs fast. Returns an empty map
// (not an error) if the file is missing, has a bad magic, or any other
// header-level problem -- callers should treat "empty map" as "skip".
fn loadPacfilesFixturesFrom(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !std.array_hash_map.Auto(BlockType, PacfileFixture) {
    var out: std.array_hash_map.Auto(BlockType, PacfileFixture) = .empty;
    errdefer {
        var it = out.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.encoded);
        }
        out.deinit(allocator);
    }

    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return out;
    defer file.close(io);

    var header_buf: [HEADER_SIZE]u8 = undefined;
    var read_buf: [16 * 1024]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    reader.interface.readSliceAll(&header_buf) catch return out;

    const hdr: *align(1) const Header = @ptrCast(&header_buf);
    if (!std.mem.eql(u8, &hdr.magic, "\x00plocate")) return out;
    if (hdr.version != 0 and hdr.version != 1) return out;

    const ht_count: usize = @intCast(hdr.hashtable_size + hdr.extra_ht_slots + 1);
    const ht_buf = try allocator.alloc(TrigramEntry, ht_count);
    defer allocator.free(ht_buf);
    const ht_bytes = std.mem.sliceAsBytes(ht_buf);
    const read = try file.readPositionalAll(io, ht_bytes, hdr.hash_table_offset_bytes);
    if (read != ht_bytes.len) return out;

    // Sort entries by offset so we can determine posting list length as
    // the delta to the next entry, mirroring `findTrigramWithLen`.
    var entries: std.ArrayList(TrigramEntry) = .empty;
    defer entries.deinit(allocator);
    for (ht_buf) |e| {
        if (e.trgm == 0) continue;
        try entries.append(allocator, e);
    }
    std.mem.sort(TrigramEntry, entries.items, {}, struct {
        fn lt(_: void, a: TrigramEntry, b: TrigramEntry) bool {
            return a.offset < b.offset;
        }
    }.lt);

    // Pick the first entry of each block type with 3 <= num_docids <= 30.
    // Stop early once every type has been found.
    var found: [4]bool = .{ false, false, false, false };
    for (entries.items) |e| {
        if (e.num_docids < 3 or e.num_docids > 30) continue;
        var tmp: [16]u8 = undefined;
        reader.seekTo(e.offset) catch continue;
        reader.interface.readSliceAll(&tmp) catch continue;
        const b0 = tmp[0];
        const bl: usize = if (b0 < 128)
            1
        else if (b0 < 192)
            2
        else if (b0 < 224)
            3
        else if (b0 < 240)
            4
        else
            continue;
        const bh = tmp[bl];
        const bt: BlockType = @enumFromInt(bh >> 6);
        if (found[@intFromEnum(bt)]) continue;

        const idx_after = blk: {
            var i: usize = 0;
            while (i < entries.items.len) : (i += 1) {
                if (entries.items[i].trgm == e.trgm and entries.items[i].offset == e.offset) break :blk i;
            }
            break :blk null;
        };
        const next_off = if (idx_after) |i|
            if (i + 1 < entries.items.len) entries.items[i + 1].offset else null
        else
            null;
        const enc_end = next_off orelse continue;
        const enc_len: usize = @intCast(enc_end - e.offset);
        if (enc_len == 0 or enc_len > 4096) continue;

        const padded = try allocator.alloc(u8, enc_len + 16);
        @memset(padded, 0);
        reader.seekTo(e.offset) catch {
            allocator.free(padded);
            continue;
        };
        reader.interface.readSliceAll(padded[0..enc_len]) catch {
            allocator.free(padded);
            continue;
        };

        try out.put(allocator, bt, .{
            .trgm = e.trgm,
            .block_type = bt,
            .num_docids = e.num_docids,
            .encoded = padded,
        });
        found[@intFromEnum(bt)] = true;
        if (found[0] and found[1] and found[2] and found[3]) break;
    }

    return out;
}

fn loadPacfilesFixtures(
    allocator: std.mem.Allocator,
    io: std.Io,
) !std.array_hash_map.Auto(BlockType, PacfileFixture) {
    return loadPacfilesFixturesFrom(allocator, io, "/var/lib/pacman/sync/core.pacfiles");
}

fn freeFixtures(
    fixtures: *std.array_hash_map.Auto(BlockType, PacfileFixture),
    allocator: std.mem.Allocator,
) void {
    var it = fixtures.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.value_ptr.encoded);
    }
    fixtures.deinit(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "plocate: readVb - single byte literal 42" {
    var out: Docid = undefined;
    const n = try readVb(&.{42}, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u32, 42), out);
}

test "plocate: readVb - max single byte 127" {
    var out: Docid = undefined;
    const n = try readVb(&.{127}, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u32, 127), out);
}

test "plocate: readVb - boundary 176 ignores trailing byte" {
    // b0 = 0b10100000 = 160 is in [0, 176] so it must consume exactly 1 byte
    // and ignore the trailing 0b00010000 sentinel.
    var out: Docid = undefined;
    const n = try readVb(&.{ 0b10100000, 0b00010000 }, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u32, 160), out);
}

test "plocate: readVb - two byte value 200" {
    // (177, 23): ((177-177)<<8 | 23) + 177 = 23 + 177 = 200.
    var out: Docid = undefined;
    const n = try readVb(&.{ 177, 23 }, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u32, 200), out);
}

test "plocate: readVb - three byte value 100000" {
    // (242, 0xEF, 0x45): ((242-241)<<16) | 0x45EF + 16561 = 100000.
    var out: Docid = undefined;
    const n = try readVb(&.{ 242, 0xEF, 0x45 }, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u32, 100000), out);
}

test "plocate: readVb - four byte 24-bit max" {
    // b0=249 stores a 24-bit LE u32 in data[1..4].
    var out: Docid = undefined;
    const n = try readVb(&.{ 249, 0xFF, 0xFF, 0xFF }, &out);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u32, 0x00FFFFFF), out);
}

test "plocate: readVb - five byte u32 max" {
    // b0=250 stores a full 32-bit LE u32 in data[1..5]; needed for 0xFFFFFFFF.
    var out: Docid = undefined;
    const n = try readVb(&.{ 250, 0xFF, 0xFF, 0xFF, 0xFF }, &out);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), out);
}

test "plocate: BitReader - all zeros" {
    const buf = [_]u32{ 0, 0, 0, 0 };
    var bs = BitReader.init(std.mem.asBytes(&buf), 8);
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(@as(u32, 0), bs.read());
    }
}

test "plocate: BitReader - all ones" {
    const buf = [_]u32{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    var bs = BitReader.init(std.mem.asBytes(&buf), 8);
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(@as(u32, 0xFF), bs.read());
    }
}

test "plocate: BitReader - alternating bit pattern LSB-first" {
    // 0xAA = 10101010b; LSB-first reads yield 0,1,0,1,0,1,0,1,...
    const buf = [_]u32{0xAAAAAAAA};
    var bs = BitReader.init(std.mem.asBytes(&buf), 1);
    for (0..32) |i| {
        const expected: u32 = if (i % 2 == 0) 0 else 1;
        try std.testing.expectEqual(expected, bs.read());
    }
}

test "plocate: BitReader - cross-lane transition" {
    const buf = [_]u32{ 0xFFFFFFFF, 0x00000000 };
    var bs = BitReader.init(std.mem.asBytes(&buf), 1);
    var ones: u32 = 0;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        if (bs.read() == 1) ones += 1;
    }
    try std.testing.expectEqual(@as(u32, 32), ones);
    // 33rd read crosses into lane 1 and returns 0.
    try std.testing.expectEqual(@as(u32, 0), bs.read());
}

test "plocate: InterleavedBitReader - basic single stream" {
    // 32-byte buffer: stream 0 occupies byte offsets 0..3 and 16..19.
    const buf = [_]u8{
        0x00, 0x01, 0x02, 0x03,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x04, 0x05, 0x06, 0x07,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    const base: [*]const u8 = &buf;
    var bs0 = InterleavedBitReader.init(4, base, 8);
    try std.testing.expectEqual(@as(u32, 0x00), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x01), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x02), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x03), bs0.read());
    // After 4 eight-bit reads, data advances by stride (16 bytes).
    try std.testing.expectEqual(@as(u32, 0x04), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x05), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x06), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x07), bs0.read());
}

test "plocate: InterleavedBitReader - cross-stream state isolation" {
    // 32-byte buffer: stream 0 at offsets 0..3, 16..19; stream 1 at 4..7, 20..23.
    const buf = [_]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    const base: [*]const u8 = &buf;
    var bs0 = InterleavedBitReader.init(4, base, 8);
    var bs1 = InterleavedBitReader.init(4, base + 4, 8);
    try std.testing.expectEqual(@as(u32, 0x00), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x04), bs1.read());
    try std.testing.expectEqual(@as(u32, 0x01), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x05), bs1.read());
    try std.testing.expectEqual(@as(u32, 0x02), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x06), bs1.read());
    try std.testing.expectEqual(@as(u32, 0x07), bs1.read());
    try std.testing.expectEqual(@as(u32, 0x03), bs0.read());
    // Both streams advance by stride after 4 reads; state is independent.
    try std.testing.expectEqual(@as(u32, 0x10), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x14), bs1.read());
}

test "plocate: InterleavedBitReader - boundary crossing" {
    const buf = [_]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    const base: [*]const u8 = &buf;
    var bs0 = InterleavedBitReader.init(4, base, 16);
    var bs1 = InterleavedBitReader.init(4, base + 4, 16);
    // bs0 reads two 16-bit values from lane 0.
    try std.testing.expectEqual(@as(u32, 0x0100), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x0302), bs0.read());
    // bs1 has not yet crossed.
    try std.testing.expectEqual(@as(u32, 0x0504), bs1.read());
    // bs0 advances to lane 1; bs1 still on lane 0.
    try std.testing.expectEqual(@as(u32, 0x1110), bs0.read());
    try std.testing.expectEqual(@as(u32, 0x0706), bs1.read());
}

test "plocate: InterleavedBitReader - all ones across streams" {
    const buf = [_]u32{
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    };
    const base: [*]const u8 = std.mem.asBytes(&buf);
    var bs0 = InterleavedBitReader.init(4, base, 32);
    var bs1 = InterleavedBitReader.init(4, base + 4, 32);
    var bs2 = InterleavedBitReader.init(4, base + 8, 32);
    var bs3 = InterleavedBitReader.init(4, base + 12, 32);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), bs0.read());
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), bs1.read());
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), bs2.read());
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), bs3.read());
}

// === PForDelta decodePostingList ===
//
// End-to-end tests for `decodePostingList`, the public PForDelta decoder
// entry point. Two complementary styles:
//
//   - Hand-crafted byte sequences cover every BlockType unconditionally.
//     They are short, self-checking, and run in any environment.
//
//   - Real-data tests read small posting lists out of
//     /var/lib/pacman/sync/core.pacfiles (the system plocate database) and
//     decode them. These catch regressions that hand-crafted cases miss but
//     are skipped when the database file is absent (e.g. on CI workers
//     without pacman). Skipping is signalled with `error.SkipZigTest` so
//     the test runner counts the test as passed-but-skipped rather than
//     failed.
//
// Allocated buffers go through `std.testing.allocator` so leaks are
// reported automatically.

test "plocate: decodePostingList - empty list (num=0)" {
    // Edge case: the public contract says num=0 returns an empty slice
    // without touching the buffer at all. We pass a tiny dummy buffer to
    // confirm no read happens.
    const allocator = std.testing.allocator;
    const result = try decodePostingList(allocator, &.{0xAA}, 0);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "plocate: decodePostingList - single docid (num=1)" {
    // Edge case: with only the baseval and no block, decodePostingList
    // should return a 1-element slice containing the baseval.
    const allocator = std.testing.allocator;
    // baseval = 0x64 = 100 (single-byte form: b0 < 128).
    var buf = [_]u8{0x64} ++ [_]u8{0} ** 16;
    const result = try decodePostingList(allocator, &buf, 1);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u32, 100), result[0]);
}

test "plocate: decodePostingList - CONSTANT block" {
    // Hand-crafted: baseval = 100, CONSTANT/8 with delta = 99, 3 docids.
    // Each iteration adds delta + 1 = 100 to the previous docid.
    // Expected: [100, 200, 300].
    const allocator = std.testing.allocator;
    var buf = [_]u8{
        0x64, // baseval = 100
        0xC8, // block header: CONSTANT, bit_width = 8
        0x63, // packed val = 99 (after 4-byte LE read + mask 0xFF)
        0x00, 0x00, 0x00, // padding so the 4-byte read doesn't reach uninit memory
    } ++ [_]u8{0} ** 16;
    const result = try decodePostingList(allocator, &buf, 3);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualSlices(Docid, &.{ 100, 200, 300 }, result);
}

test "plocate: decodePostingList - FOR block" {
    // Hand-crafted: baseval = 50, FOR/8 with 4 deltas [10, 20, 30, 40].
    // Each delta contributes delta + 1 to the running sum.
    // Expected: [50, 61, 82, 113, 154].
    const allocator = std.testing.allocator;
    var buf = [_]u8{
        0x32, // baseval = 50
        0x08, // block header: FOR, bit_width = 8
        0x0A, 0x14, 0x1E, 0x28, // deltas packed LE: 10, 20, 30, 40
    } ++ [_]u8{0} ** 16;
    const result = try decodePostingList(allocator, &buf, 5);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualSlices(Docid, &.{ 50, 61, 82, 113, 154 }, result);
}

test "plocate: decodePostingList - PFOR_VB with one exception" {
    // Hand-crafted: baseval = 1000, PFOR_VB/4 with 2 deltas and 1 exception.
    //   delta[0] = 3 (low 4 = 3, no exception)
    //   delta[1] = 0x645: low 4 = 5, exception = 100 (shifted left by 4)
    // Expected: [1000, 1004, 1004 + 1605 + 1 = 2610].
    const allocator = std.testing.allocator;
    var buf = [_]u8{
        0x83, 0xE8, // baseval = 1000 (2-byte PrefixVarint form)
        0x44, // block header: PFOR_VB, bit_width = 4
        0x01, // num_exceptions = 1
        0x53, // 2 deltas of 4 bits: low nibble = 3, high nibble = 5
        0x64, // exception value 100, VB-encoded as single byte
        0x01, // exception index = 1
    } ++ [_]u8{0} ** 16;
    const result = try decodePostingList(allocator, &buf, 3);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualSlices(Docid, &.{ 1000, 1004, 2610 }, result);
}

test "plocate: decodePostingList - PFOR_BITMAP with one exception" {
    // Hand-crafted: baseval = 100, PFOR_BITMAP/4 with 4 deltas and 1 exception.
    //   delta[0] = 3 (low 4 = 3, no exception)
    //   delta[1] = 5 (low 4 = 5, no exception)
    //   delta[2] = 7 | (100 << 4) = 0x647 = 1607 (exception at index 2)
    //   delta[3] = 9 (low 4 = 9, no exception)
    // Expected: [100, 104, 110, 1718, 1728].
    //
    // Layout: header, exception width, 1-byte bitmap, exception value, then
    // the 4-bit base values packed as 2 bytes. decodePforBitmapExceptions
    // reads the bitmap as a u64, so pad after the real data to keep the read
    // well-defined.
    const allocator = std.testing.allocator;
    var buf = [_]u8{
        0x64, // baseval = 100
        0x84, // block header: PFOR_BITMAP, bit_width = 4
        0x08, // exception_bit_width = 8
        0x04, // bitmap: bit 2 set => exception at index 2
        0x64, // exception value = 100
        0x53, 0x97, // 4 deltas of 4 bits: [3, 5, 7, 9]
    } ++ [_]u8{0} ** 16;
    const result = try decodePostingList(allocator, &buf, 5);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualSlices(Docid, &.{ 100, 104, 110, 1718, 1728 }, result);
}

test "plocate: decodePostingList - real FOR block from core.pacfiles" {
    const allocator = std.testing.allocator;
    var fixtures = loadPacfilesFixtures(allocator, std.testing.io) catch
        return error.SkipZigTest;
    defer freeFixtures(&fixtures, allocator);

    const fx = fixtures.getPtr(.FOR) orelse return error.SkipZigTest;
    const decoded = try decodePostingList(allocator, fx.encoded, fx.num_docids);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, fx.num_docids), decoded.len);
    for (decoded[0 .. decoded.len - 1], decoded[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}

test "plocate: decodePostingList - real CONSTANT block from core.pacfiles" {
    const allocator = std.testing.allocator;
    var fixtures = loadPacfilesFixtures(allocator, std.testing.io) catch
        return error.SkipZigTest;
    defer freeFixtures(&fixtures, allocator);

    const fx = fixtures.getPtr(.CONSTANT) orelse return error.SkipZigTest;
    const decoded = try decodePostingList(allocator, fx.encoded, fx.num_docids);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, fx.num_docids), decoded.len);
    for (decoded[0 .. decoded.len - 1], decoded[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}

test "plocate: decodePostingList - real PFOR_VB block from core.pacfiles" {
    const allocator = std.testing.allocator;
    var fixtures = loadPacfilesFixtures(allocator, std.testing.io) catch
        return error.SkipZigTest;
    defer freeFixtures(&fixtures, allocator);

    const fx = fixtures.getPtr(.PFOR_VB) orelse return error.SkipZigTest;
    const decoded = try decodePostingList(allocator, fx.encoded, fx.num_docids);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, fx.num_docids), decoded.len);
    for (decoded[0 .. decoded.len - 1], decoded[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}

test "plocate: decodePostingList - real PFOR_BITMAP block from core.pacfiles" {
    const allocator = std.testing.allocator;
    var fixtures = loadPacfilesFixtures(allocator, std.testing.io) catch
        return error.SkipZigTest;
    defer freeFixtures(&fixtures, allocator);

    const fx = fixtures.getPtr(.PFOR_BITMAP) orelse return error.SkipZigTest;
    const decoded = try decodePostingList(allocator, fx.encoded, fx.num_docids);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, fx.num_docids), decoded.len);
    for (decoded[0 .. decoded.len - 1], decoded[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}

test "plocate: decodePostingList - skips gracefully when pacfiles missing" {
    // Standalone "no DB available" test: verifies that loadPacfilesFixtures
    // returns an empty map (not an error) when the database file is absent,
    // so callers can just early-return without failure.
    const allocator = std.testing.allocator;

    // Force the failure path with a path that cannot exist.
    var empty = try loadPacfilesFixturesFrom(allocator, std.testing.io, "/nonexistent.pacfiles");
    defer freeFixtures(&empty, allocator);
    try std.testing.expectEqual(@as(usize, 0), empty.count());
}

test "plocate: decodePostingList - real multi-block posting list" {
    // Picks the smallest posting list with num_docids >= 129 from the
    // system DB. A 129-docid list forces two blocks: a full 128-element
    // block (which exercises the interleaved decoders) followed by a
    // 1-element partial block (which exercises the non-interleaved path
    // for the same BlockType). This is the only test that hits the
    // interleaved codepath end-to-end.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const path = "/var/lib/pacman/sync/core.pacfiles";
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return error.SkipZigTest;
    defer file.close(io);

    var header_buf: [HEADER_SIZE]u8 = undefined;
    var read_buf: [16 * 1024]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    reader.interface.readSliceAll(&header_buf) catch return error.SkipZigTest;
    const hdr: *align(1) const Header = @ptrCast(&header_buf);
    if (!std.mem.eql(u8, &hdr.magic, "\x00plocate")) return error.SkipZigTest;
    if (hdr.version != 0 and hdr.version != 1) return error.SkipZigTest;

    const ht_count: usize = @intCast(hdr.hashtable_size + hdr.extra_ht_slots + 1);
    const ht_buf = try allocator.alloc(TrigramEntry, ht_count);
    defer allocator.free(ht_buf);
    const ht_bytes = std.mem.sliceAsBytes(ht_buf);
    const read = try file.readPositionalAll(io, ht_bytes, hdr.hash_table_offset_bytes);
    if (read != ht_bytes.len) return error.SkipZigTest;

    var entries: std.ArrayList(TrigramEntry) = .empty;
    defer entries.deinit(allocator);
    for (ht_buf) |e| {
        if (e.trgm == 0) continue;
        try entries.append(allocator, e);
    }
    std.mem.sort(TrigramEntry, entries.items, {}, struct {
        fn lt(_: void, a: TrigramEntry, b: TrigramEntry) bool {
            return a.offset < b.offset;
        }
    }.lt);

    // Pick the smallest entry with num_docids >= 129.
    var chosen: ?TrigramEntry = null;
    for (entries.items) |e| {
        if (e.num_docids >= 129) {
            chosen = e;
            break;
        }
    }
    const e = chosen orelse return error.SkipZigTest;

    // Determine posting list length as offset delta to next entry.
    var idx: usize = 0;
    while (idx < entries.items.len) : (idx += 1) {
        if (entries.items[idx].trgm == e.trgm and entries.items[idx].offset == e.offset) break;
    }
    if (idx + 1 >= entries.items.len) return error.SkipZigTest;
    const enc_len: usize = @intCast(entries.items[idx + 1].offset - e.offset);

    const padded = try allocator.alloc(u8, enc_len + 16);
    defer allocator.free(padded);
    @memset(padded, 0);
    reader.seekTo(e.offset) catch return error.SkipZigTest;
    reader.interface.readSliceAll(padded[0..enc_len]) catch return error.SkipZigTest;

    const decoded = try decodePostingList(allocator, padded, e.num_docids);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, e.num_docids), decoded.len);
    for (decoded[0 .. decoded.len - 1], decoded[1..]) |a, b| {
        try std.testing.expect(a <= b);
    }
}
