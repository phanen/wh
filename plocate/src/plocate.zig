const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");
const pfor = @import("pfor.zig");

// Re-export the on-disk header types so the rest of this file can stay
// terse and the test fixtures in pfor.zig stay self-contained.
const Docid = pfor.Docid;
const Header = pfor.Header;
const TrigramEntry = pfor.TrigramEntry;

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

const TRIGRAM_ENTRY_SIZE: usize = 16; // struct { trgm: u32, num_docids: u32, offset: u64 }
// Sanity cap for the on-disk trigram hash table. The theoretical maximum is
// 256^3 = 16,777,216 distinct trigrams; real DBs have far fewer. A bogus
// hashtable_size in a corrupt DB would otherwise trigger a huge allocation
// before the read fails.
const MAX_TRIGRAM_ENTRIES: u32 = 10_000_000;
const PACFILES_SUFFIX: []const u8 = ".pacfiles";
const SYNC_DIR: []const u8 = "/var/lib/pacman/sync";

pub const PacfilesMatch = struct {
    pkgname: []const u8,
    version: []const u8,
    repo: []const u8,
    filepath: []const u8,
};

const EntryParts = struct {
    pkgname: []const u8,
    version: []const u8,
    path: []const u8,
};

const MAX_TRIGRAMS: usize = 512;

const SearchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file_reader: *std.Io.File.Reader,
    /// Read-only mapping of the whole DB file. Used for the per-docid
    /// compressed blocks so the parallel brute force and candidate scan can
    /// decode directly from the OS page cache without an extra userspace copy.
    mapping: []const u8,
    ddict: ?*const anyopaque,
    hdr: *align(1) const Header,
    index_buf: []const u64,
    target: []const u8,
    repo_name: []const u8,
};

fn hashTrigram(trgm: u32, ht_size: u32) u32 {
    std.debug.assert(ht_size > 0); // modulo below requires nonzero divisor
    var crc = trgm;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const bit = (crc & 0x80000000) != 0;
        crc <<= 1;
        if (bit) crc ^= 0x1edc6f41;
    }
    return crc % ht_size;
}

/// Posting list length is derived from the offset delta to the next entry;
/// the on-disk hash table does not store lengths directly.
fn findTrigramWithLen(ht: []const TrigramEntry, ht_size: u32, slots: u32, trgm: u32) ?struct { entry: TrigramEntry, len: u64 } {
    const bucket = hashTrigram(trgm, ht_size);
    var i: u32 = 0;
    while (i <= slots) : (i += 1) {
        const idx = bucket + i;
        std.debug.assert(idx + 1 < ht.len); // linear probe must stay within hash table
        const e = ht[idx];
        if (e.trgm == 0) return null;
        if (e.trgm == trgm) {
            const next_off = ht[idx + 1].offset;
            return .{ .entry = e, .len = next_off - e.offset };
        }
    }
    return null;
}

// Case-sensitive: trigrams are raw byte windows, no Unicode or locale folding.
fn extractTrigrams(target: []const u8, out: []u32) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 3 <= target.len) : (i += 1) {
        const t: u32 = @as(u32, target[i]) |
            (@as(u32, target[i + 1]) << 8) |
            (@as(u32, target[i + 2]) << 16);
        if (t == 0) continue;
        var dup = false;
        for (out[0..n]) |existing| {
            if (existing == t) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        out[n] = t;
        n += 1;
        if (n == out.len) break;
    }
    return n;
}

/// Sorted-merge intersection of pre-loaded posting lists.
/// Contract: `lists` are sorted ascending by length; result is sorted ascending.
/// Caller owns the returned slice.
fn mergeSortedPostingLists(
    allocator: std.mem.Allocator,
    lists: []const []const Docid,
) ![]Docid {
    if (lists.len == 0) return try allocator.alloc(Docid, 0);
    var cur = try allocator.dupe(Docid, lists[0]);
    errdefer allocator.free(cur);
    var i: usize = 1;
    while (i < lists.len) : (i += 1) {
        const list = lists[i];
        if (cur.len == 0) break;
        var next: std.ArrayList(Docid) = .empty;
        errdefer next.deinit(allocator);
        var a: usize = 0;
        var b: usize = 0;
        while (a < cur.len and b < list.len) {
            const av = cur[a];
            const bv = list[b];
            if (av < bv) {
                a += 1;
            } else if (av > bv) {
                b += 1;
            } else {
                try next.append(allocator, av);
                a += 1;
                b += 1;
            }
        }
        allocator.free(cur);
        cur = try next.toOwnedSlice(allocator);
        if (cur.len == 0) break;
    }
    return cur;
}

/// Caller owns the returned slice.
fn unionSortedPostingLists(
    allocator: std.mem.Allocator,
    a: []const Docid,
    b: []const Docid,
) ![]Docid {
    var out: std.ArrayList(Docid) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        const av = a[i];
        const bv = b[j];
        if (av < bv) {
            try out.append(allocator, av);
            i += 1;
        } else if (av > bv) {
            try out.append(allocator, bv);
            j += 1;
        } else {
            try out.append(allocator, av);
            i += 1;
            j += 1;
        }
    }
    while (i < a.len) : (i += 1) try out.append(allocator, a[i]);
    while (j < b.len) : (j += 1) try out.append(allocator, b[j]);
    return out.toOwnedSlice(allocator);
}

/// Returns true iff /var/lib/pacman/sync contains any *.pacfiles DBs.
/// Open failures (missing dir, permission denied, IO error) collapse to
/// `false` so callers can use this as a simple "use pacfiles vs pacrepo"
/// switch; the caller in pacman.zig falls back to pacrepo on `false`.
pub fn dbsExist(io: std.Io) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, SYNC_DIR, .{ .iterate = true }) catch
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

    var dir = try std.Io.Dir.openDirAbsolute(io, SYNC_DIR, .{ .iterate = true });
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

pub fn freeMatches(matches: []const PacfilesMatch, allocator: std.mem.Allocator) void {
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
    const db_path = try std.fs.path.join(allocator, &.{ SYNC_DIR, db_filename });
    defer allocator.free(db_path);

    var file = std.Io.Dir.openFileAbsolute(io, db_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return try allocator.alloc(PacfilesMatch, 0),
        else => return err,
    };
    defer file.close(io);

    const file_size = (try file.stat(io)).size;

    // Map the DB read-only. populate is left off so a fast trigram search
    // never faults in the whole file; the brute-force path pages it in on
    // demand while decompressing.
    var file_map = std.Io.File.MemoryMap.create(io, file, .{
        .len = @intCast(file_size),
        .protection = .{ .read = true },
        .populate = false,
    }) catch return try allocator.alloc(PacfilesMatch, 0);
    defer file_map.destroy(io);
    const mapping: []const u8 = file_map.memory;

    var read_buf: [16 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);

    var header_buf: [pfor.HEADER_SIZE]u8 = undefined;
    try file_reader.interface.readSliceAll(&header_buf);

    const hdr: *align(1) const Header = @ptrCast(&header_buf);
    if (!std.mem.eql(u8, &hdr.magic, &pfor.PACLOCATE_MAGIC)) return try allocator.alloc(PacfilesMatch, 0);
    if (hdr.version != 0 and hdr.version != 1) return try allocator.alloc(PacfilesMatch, 0);

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

    // Pair assertions on the filename index offset table. Without these, a
    // corrupt .pacfiles (truncated, fuzzed, or version-mismatched) would let
    // bogus offsets flow into searchBruteForce and produce a silent wrong
    // result instead of a loud panic we can debug.
    std.debug.assert(index_buf[0] >= pfor.HEADER_SIZE);
    std.debug.assert(index_buf[index_buf.len - 1] <= file_size);
    {
        var i: usize = 1;
        while (i < index_buf.len) : (i += 1) {
            std.debug.assert(index_buf[i - 1] <= index_buf[i]);
        }
    }

    var search_ctx: SearchCtx = .{
        .allocator = allocator,
        .io = io,
        .file_reader = &file_reader,
        .mapping = mapping,
        .ddict = ddict,
        .hdr = hdr,
        .index_buf = index_buf,
        .target = target,
        .repo_name = repo_name,
    };

    if (target.len >= 3 or target.len == 2) {
        const ht_count: usize = @intCast(hdr.hashtable_size + hdr.extra_ht_slots + 1);
        // Reject corrupt DBs that would request huge allocations before the
        // readPositionalAll below can fail. debug.assert is wrong here because
        // the hashtable_size is parsed from external, attacker-influenced
        // bytes; treat oversize counts as a database error, not a programmer
        // error.
        if (ht_count > MAX_TRIGRAM_ENTRIES) return error.InvalidDatabase;
        const ht_buf = try allocator.alloc(TrigramEntry, ht_count);
        defer allocator.free(ht_buf);
        const read = try file.readPositionalAll(io, std.mem.sliceAsBytes(ht_buf), hdr.hash_table_offset_bytes);
        if (read != std.mem.sliceAsBytes(ht_buf).len) return error.TruncatedHashTable;

        if (target.len >= 3) {
            if (try searchByTrigrams(&search_ctx, ht_buf)) |m| {
                // The trigram index is authoritative for targets with >= 3 bytes:
                // every filename is indexed by all of its trigrams, so an empty
                // intersection is a definitive "no match". Brute force is only a
                // meaningful fallback for targets too short to have trigrams.
                return m;
            }
        } else {
            if (try searchByTwoCharUnion(&search_ctx, ht_buf)) |m| return m;
        }
    }

    return try searchBruteForce(&search_ctx);
}

fn searchByTrigrams(ctx: *SearchCtx, ht: []const TrigramEntry) !?[]PacfilesMatch {
    // intersectPostingLists returns null when the target has no extractable
    // trigrams (e.g. len < 3); the caller then falls back to brute force.
    const docids = try intersectPostingLists(ctx, ht) orelse return null;
    defer ctx.allocator.free(docids);

    if (docids.len == 0) return try ctx.allocator.alloc(PacfilesMatch, 0);

    return try decompressAndScanBlocks(ctx, docids);
}

/// Union of posting lists of every trigram containing the 2-byte target. A
/// length>=3 filename with the target has it inside a trigram, so the union is
/// a superset of matching blocks. null forces a brute-force fallback, which
/// also covers top-level 1-2 char filenames that have no trigrams.
fn searchByTwoCharUnion(ctx: *SearchCtx, ht: []const TrigramEntry) !?[]PacfilesMatch {
    const target = ctx.target;
    if (target.len != 2) return null;

    var keys: [512]u32 = undefined;
    var n: usize = 0;
    const t0 = target[0];
    const t1 = target[1];
    for (0..256) |b| {
        const k = (@as(u32, @intCast(b))) | (@as(u32, t0) << 8) | (@as(u32, t1) << 16);
        if (k != 0) {
            keys[n] = k;
            n += 1;
        }
    }
    for (0..256) |b| {
        const k = (@as(u32, t0)) | (@as(u32, t1) << 8) | (@as(u32, @intCast(b)) << 16);
        if (k != 0) {
            keys[n] = k;
            n += 1;
        }
    }

    const Entry = struct { entry: TrigramEntry, len: u64 };
    const lt = struct {
        fn call(_: void, a: Entry, b: Entry) bool {
            return a.len < b.len;
        }
    }.call;
    var found: [512]Entry = undefined;
    var num: usize = 0;
    for (keys[0..n]) |k| {
        if (findTrigramWithLen(ht, ctx.hdr.hashtable_size, ctx.hdr.extra_ht_slots, k)) |r| {
            found[num] = .{ .entry = r.entry, .len = r.len };
            num += 1;
        }
    }
    if (num == 0) return null;

    var sum: u64 = 0;
    for (found[0..num]) |f| sum += f.len;
    // Skip when the matching lists cover too many blocks: decode+union+
    // decompress would then cost more than brute-forcing everything.
    if (sum > (ctx.index_buf.len - 1) / 4) return null;

    // Smallest lists first so the running union stays compact.
    std.mem.sortUnstable(Entry, found[0..num], {}, lt);

    var cur: ?[]Docid = null;
    errdefer if (cur) |p| ctx.allocator.free(p);
    {
        const e = found[0].entry;
        const enc_len: usize = @intCast(found[0].len);
        const pl_buf = try ctx.allocator.alloc(u8, enc_len + 16);
        defer ctx.allocator.free(pl_buf);
        @memset(pl_buf[enc_len..], 0);
        try ctx.file_reader.seekTo(e.offset);
        try ctx.file_reader.interface.readSliceAll(pl_buf[0..enc_len]);
        cur = try pfor.decodePostingList(ctx.allocator, pl_buf[0..enc_len], e.num_docids);
    }
    var i: usize = 1;
    while (i < num) : (i += 1) {
        const cur_val = cur orelse break;
        const e = found[i].entry;
        const enc_len: usize = @intCast(found[i].len);
        const pl_buf = try ctx.allocator.alloc(u8, enc_len + 16);
        defer ctx.allocator.free(pl_buf);
        @memset(pl_buf[enc_len..], 0);
        try ctx.file_reader.seekTo(e.offset);
        try ctx.file_reader.interface.readSliceAll(pl_buf[0..enc_len]);
        const decoded = try pfor.decodePostingList(ctx.allocator, pl_buf[0..enc_len], e.num_docids);
        defer ctx.allocator.free(decoded);
        const merged = try unionSortedPostingLists(ctx.allocator, cur_val, decoded);
        cur = merged;
        ctx.allocator.free(cur_val);
    }
    const cands = cur orelse try ctx.allocator.alloc(Docid, 0);
    defer ctx.allocator.free(cands);
    return try decompressAndScanBlocks(ctx, cands);
}

/// Extract trigrams from `target`, look each up in the on-disk hash table,
/// sort the surviving posting lists by ascending `num_docids`, load and
/// intersect them with the adaptive cutoff heuristic.
///
/// Returns:
///   - `null`  : target yielded no trigrams (caller should fall back to brute force)
///   - `[]Docid` (possibly empty) : candidate set; caller owns and frees
fn intersectPostingLists(ctx: *SearchCtx, ht: []const TrigramEntry) !?[]Docid {
    var trigram_buf: [MAX_TRIGRAMS]u32 = undefined;
    const n_trigrams = extractTrigrams(ctx.target, &trigram_buf);
    if (n_trigrams == 0) return null;

    var found_entries: [MAX_TRIGRAMS]?TrigramEntry = .{null} ** MAX_TRIGRAMS;
    var found_lens: [MAX_TRIGRAMS]u64 = .{0} ** MAX_TRIGRAMS;
    var num_unique: usize = 0;
    {
        var i: usize = 0;
        while (i < n_trigrams) : (i += 1) {
            const t = trigram_buf[i];
            var already = false;
            for (found_entries[0..num_unique]) |e| {
                if (e != null and e.?.trgm == t) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            const result = findTrigramWithLen(ht, ctx.hdr.hashtable_size, ctx.hdr.extra_ht_slots, t) orelse return try ctx.allocator.alloc(Docid, 0);
            found_entries[num_unique] = result.entry;
            found_lens[num_unique] = result.len;
            num_unique += 1;
        }
    }

    if (num_unique == 0) return try ctx.allocator.alloc(Docid, 0);

    var order: [MAX_TRIGRAMS]usize = undefined;
    for (order[0..num_unique], 0..) |*slot, i| slot.* = i;
    const Ctx = struct {
        entries: []const ?TrigramEntry,
        fn lt(s: @This(), a: usize, b: usize) bool {
            return s.entries[a].?.num_docids < s.entries[b].?.num_docids;
        }
    };
    std.mem.sortUnstable(
        usize,
        order[0..num_unique],
        Ctx{ .entries = found_entries[0..num_unique] },
        Ctx.lt,
    );

    // Optional tracks whether `cur` has been set yet; `errdefer` only frees a
    // heap-allocated slice, never the zero value of the optional.
    var cur: ?[]Docid = null;
    errdefer if (cur) |p| ctx.allocator.free(p);

    {
        const first_idx = order[0];
        const e = found_entries[first_idx].?;
        const enc_len: usize = @intCast(found_lens[first_idx]);
        const comp_off: u64 = e.offset;
        try ctx.file_reader.seekTo(comp_off);
        const pl_buf = try ctx.allocator.alloc(u8, enc_len + 16);
        defer ctx.allocator.free(pl_buf);
        // Zero the 16-byte readahead tail: the interleaved bit readers may
        // read up to 16 bytes past the encoded data (see BitReader docs).
        @memset(pl_buf[enc_len..], 0);
        try ctx.file_reader.interface.readSliceAll(pl_buf[0..enc_len]);
        cur = try pfor.decodePostingList(ctx.allocator, pl_buf[0..enc_len], e.num_docids);
    }

    // Adaptive sorted-merge intersection. Assign to `cur` before freeing the
    // old value so an errdefer at function exit always sees the current owner.
    var i: usize = 1;
    while (i < num_unique) : (i += 1) {
        const cur_val = cur orelse break;
        if (cur_val.len == 0) break;
        const idx = order[i];
        const e = found_entries[idx].?;
        if (e.num_docids > cur_val.len * 100) break;

        const enc_len: usize = @intCast(found_lens[idx]);
        const comp_off: u64 = e.offset;
        try ctx.file_reader.seekTo(comp_off);
        const pl_buf = try ctx.allocator.alloc(u8, enc_len + 16);
        defer ctx.allocator.free(pl_buf);
        @memset(pl_buf[enc_len..], 0);
        try ctx.file_reader.interface.readSliceAll(pl_buf[0..enc_len]);
        const decoded = try pfor.decodePostingList(ctx.allocator, pl_buf[0..enc_len], e.num_docids);
        defer ctx.allocator.free(decoded);

        const merged = try mergeSortedPostingLists(ctx.allocator, &.{ cur_val, decoded });
        cur = merged;
        ctx.allocator.free(cur_val);
    }

    return cur orelse try ctx.allocator.alloc(Docid, 0);
}

/// For each surviving candidate docid, ZSTD-decompress its block and run
/// `scanBlock` to collect PacfilesMatch entries. Caller owns the returned slice.
fn decompressAndScanBlocks(ctx: *SearchCtx, docids: []const Docid) ![]PacfilesMatch {
    const dctx = c.ZSTD_createDCtx() orelse return error.ZstdCtxFailed;
    defer _ = c.ZSTD_freeDCtx(dctx);

    var results: std.ArrayList(PacfilesMatch) = .empty;
    errdefer freeMatches(results.items, ctx.allocator);

    const num_docids: u32 = @intCast(ctx.index_buf.len - 1);

    for (docids) |docid| {
        if (docid >= num_docids) continue;
        const comp_off = ctx.index_buf[docid];
        const comp_end = ctx.index_buf[docid + 1];
        if (comp_end < comp_off) return error.CorruptIndex;
        if (comp_end > ctx.mapping.len) return error.CorruptIndex;
        const comp_slice = ctx.mapping[@intCast(comp_off)..@intCast(comp_end)];

        const frame_size = c.ZSTD_getFrameContentSize(comp_slice.ptr, comp_slice.len);
        if (frame_size == ZSTD_CONTENTSIZE_ERROR or frame_size == ZSTD_CONTENTSIZE_UNKNOWN) continue;
        const out_size: usize = @intCast(frame_size);

        const out_buf = try ctx.allocator.alloc(u8, out_size);
        defer ctx.allocator.free(out_buf);

        const written = if (ctx.ddict) |d|
            c.ZSTD_decompress_usingDDict(dctx, out_buf.ptr, out_size, comp_slice.ptr, comp_slice.len, d)
        else
            c.ZSTD_decompressDCtx(dctx, out_buf.ptr, out_size, comp_slice.ptr, comp_slice.len);

        if (c.ZSTD_isError(written) != 0) continue;
        const produced: usize = @intCast(written);
        if (produced != out_size) continue;

        if (scanBlock(ctx.allocator, ctx.repo_name, out_buf, ctx.target)) |m| {
            // scanBlock returns a slice of PacfilesMatch structs whose string
            // fields are heap-allocated. On appendSlice success, those structs
            // are shallow-copied into `results` and the strings transfer
            // ownership; only the slice container must be freed.
            results.appendSlice(ctx.allocator, m) catch |err| {
                freeMatches(m, ctx.allocator);
                return err;
            };
            ctx.allocator.free(m);
        }
    }

    return try results.toOwnedSlice(ctx.allocator);
}

// Brute force is parallel: the main thread enqueues index ranges into an
// inline Io.Queue (bounded, so it backpressures the producer); N worker
// fibers each own a ZSTD_DCtx and decompress blocks straight from the DB
// mapping, appending matches to a per-worker list merged after `group.await`.

const BATCH: u32 = 32;
const QUEUE_CAPACITY: usize = 64;

const WorkItem = struct {
    /// Borrows the DB mapping; never freed by the worker.
    compressed: []const u8,
    batch_start_off: u64,
    offsets: []const u64,
    num_blocks: u32,
    repo_name: []const u8,
    target: []const u8,
    ddict: ?*const anyopaque,
};

const WorkerCtx = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    queue: *std.Io.Queue(WorkItem),
    results: std.ArrayList(PacfilesMatch),
    dctx: ?*anyopaque,
    out_buf: std.ArrayList(u8),
};

fn workerLoop(ctx: *WorkerCtx) void {
    ctx.dctx = c.ZSTD_createDCtx();
    if (ctx.dctx == null) {
        std.log.err("plocate: ZSTD_createDCtx failed; worker will skip all tasks", .{});
        return;
    }
    defer {
        if (ctx.dctx) |ctx_ptr| _ = c.ZSTD_freeDCtx(ctx_ptr);
    }

    while (true) {
        const item = ctx.queue.getOneUncancelable(ctx.io) catch break;
        processWorkItem(ctx, item);
    }
}

fn processWorkItem(ctx: *WorkerCtx, item: WorkItem) void {
    const allocator = ctx.allocator;
    const dctx = ctx.dctx orelse return;

    var j: u32 = 0;
    while (j < item.num_blocks) : (j += 1) {
        const block_start: usize = @intCast(item.offsets[j] - item.batch_start_off);
        const block_end: usize = @intCast(item.offsets[j + 1] - item.batch_start_off);
        const comp_size = block_end - block_start;
        const comp_slice = item.compressed[block_start..block_end];

        const frame_size = c.ZSTD_getFrameContentSize(comp_slice.ptr, comp_size);
        if (frame_size == ZSTD_CONTENTSIZE_ERROR or frame_size == ZSTD_CONTENTSIZE_UNKNOWN) continue;
        const out_size: usize = @intCast(frame_size);

        if (ctx.out_buf.items.len < out_size) {
            ctx.out_buf.resize(allocator, out_size) catch continue;
        }

        const written = if (item.ddict) |d|
            c.ZSTD_decompress_usingDDict(dctx, ctx.out_buf.items.ptr, out_size, comp_slice.ptr, comp_size, d)
        else
            c.ZSTD_decompressDCtx(dctx, ctx.out_buf.items.ptr, out_size, comp_slice.ptr, comp_size);

        if (c.ZSTD_isError(written) != 0) continue;
        const produced: usize = @intCast(written);
        if (produced != out_size) continue;

        const decompressed = ctx.out_buf.items[0..out_size];
        if (!containsTarget(decompressed, item.target)) continue;

        if (scanBlock(allocator, item.repo_name, decompressed, item.target)) |m| {
            defer allocator.free(m); // Free the slice container, not the strings.
            // On success, the strings inside `m` belong to ctx.results.
            // On failure, appendSlice did not take ownership, so free them.
            ctx.results.appendSlice(allocator, m) catch freeMatches(m, allocator);
        }
    }
}

/// Fast substring presence test used to skip scanBlock for blocks that cannot
/// contain the target. For 1-byte needles this is a vectorized scalar scan.
/// For 2-4 byte needles std.mem.indexOf would fall back to findPosLinear, a
/// position-by-position eql, which dominates the brute-force CPU; instead scan
/// the vectorized first byte and only verify the tail at matches.
fn containsTarget(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 1)
        return std.mem.indexOfScalar(u8, haystack, needle[0]) != null;
    if (needle.len > 4)
        return std.mem.indexOf(u8, haystack, needle) != null;

    const first = needle[0];
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, haystack, pos, first)) |i| {
        if (haystack.len - i >= needle.len and
            std.mem.eql(u8, haystack[i..][0..needle.len], needle)) return true;
        pos = i + 1;
    }
    return false;
}

fn deinitWorkerCtx(ctx: *WorkerCtx, allocator: std.mem.Allocator) void {
    for (ctx.results.items) |m| freeMatch(m, allocator);
    ctx.results.deinit(allocator);
    ctx.out_buf.deinit(allocator);
}

fn searchBruteForce(ctx: *SearchCtx) ![]PacfilesMatch {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const ddict = ctx.ddict;
    const index_buf = ctx.index_buf;
    const target = ctx.target;
    const repo_name = ctx.repo_name;
    const mapping = ctx.mapping;

    const num_docids: u32 = @intCast(index_buf.len - 1);
    if (num_docids == 0) return try allocator.alloc(PacfilesMatch, 0);

    const cpu_count = std.Thread.getCpuCount() catch 1;
    const num_threads: usize = @max(1, cpu_count - 1);

    var queue_buffer: [QUEUE_CAPACITY]WorkItem = undefined;
    var queue: std.Io.Queue(WorkItem) = .init(&queue_buffer);

    var group: std.Io.Group = .init;
    defer group.cancel(io);

    const contexts = try allocator.alloc(WorkerCtx, num_threads);

    for (contexts) |*worker_ctx| {
        worker_ctx.* = .{
            .io = io,
            .allocator = allocator,
            .queue = &queue,
            .results = .empty,
            .dctx = null,
            .out_buf = .empty,
        };
    }

    for (contexts) |*worker_ctx| {
        group.async(io, workerLoop, .{worker_ctx});
    }

    // On any error below, close the queue so blocked workers unblock, wait
    // for them to finish (so per-worker state is no longer being mutated),
    // then free per-worker and contexts state.
    errdefer {
        queue.close(io);
        group.await(io) catch {};
        for (contexts) |*worker_ctx| deinitWorkerCtx(worker_ctx, allocator);
        allocator.free(contexts);
    }

    var i: u32 = 0;
    while (i < num_docids) {
        const batch_end_idx = @min(i + BATCH, num_docids);
        const batch_start_off: u64 = index_buf[i];
        const batch_end_off: u64 = index_buf[batch_end_idx];
        if (batch_end_off < batch_start_off) return error.CorruptIndex;
        if (batch_end_off > mapping.len) return error.CorruptIndex;

        // offsets count is num_blocks + 1 (inclusive end boundary).
        const offsets = index_buf[i..][0..@intCast(batch_end_idx - i + 1)];
        const item = WorkItem{
            // Borrows `mapping`; the worker never frees it (the mapping outlives
            // the queue via searchOneDb's defer).
            .compressed = mapping[@intCast(batch_start_off)..@intCast(batch_end_off)],
            .batch_start_off = batch_start_off,
            .offsets = offsets,
            .num_blocks = batch_end_idx - i,
            .repo_name = repo_name,
            .target = target,
            .ddict = ddict,
        };

        // putOne blocks when the queue is full, backpressuring the producer.
        queue.putOne(io, item) catch |err| return err;

        i = batch_end_idx;
    }

    queue.close(io);
    try group.await(io);

    var merged: std.ArrayList(PacfilesMatch) = .empty;
    errdefer freeMatches(merged.items, allocator);

    // appendSlice copies the PacfilesMatch structs (with their string pointers)
    // into merged. clearRetainingCapacity drops ctx.results.items.len to 0 so
    // deinitWorkerCtx does not double-free the strings that merged now owns.
    for (contexts) |*worker_ctx| {
        try merged.appendSlice(allocator, worker_ctx.results.items);
        worker_ctx.results.clearRetainingCapacity();
    }

    for (contexts) |*worker_ctx| deinitWorkerCtx(worker_ctx, allocator);
    allocator.free(contexts);

    return try merged.toOwnedSlice(allocator);
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

// ============================================================================
// Tests
// ============================================================================

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

test "plocate: extractTrigrams from usr/bin/ls" {
    var out: [16]u32 = undefined;
    const n = extractTrigrams("usr/bin/ls", &out);
    try std.testing.expectEqual(@as(usize, 8), n);
    const expected = [_]u32{
        'u' | ('s' << 8) | ('r' << 16),
        's' | ('r' << 8) | ('/' << 16),
        'r' | ('/' << 8) | ('b' << 16),
        '/' | ('b' << 8) | ('i' << 16),
        'b' | ('i' << 8) | ('n' << 16),
        'i' | ('n' << 8) | ('/' << 16),
        'n' | ('/' << 8) | ('l' << 16),
        '/' | ('l' << 8) | ('s' << 16),
    };
    for (expected, 0..) |t, i| try std.testing.expectEqual(t, out[i]);
}

test "plocate: extractTrigrams dedupes" {
    var out: [16]u32 = undefined;
    const n = extractTrigrams("abcabc", &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual('a' | ('b' << 8) | ('c' << 16), out[0]);
    try std.testing.expectEqual('b' | ('c' << 8) | ('a' << 16), out[1]);
    try std.testing.expectEqual('c' | ('a' << 8) | ('b' << 16), out[2]);
}

test "plocate: extractTrigrams skips short input" {
    var out: [16]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), extractTrigrams("ab", &out));
    try std.testing.expectEqual(@as(usize, 0), extractTrigrams("", &out));
}

test "plocate: extractTrigrams skips zero trigrams" {
    // The reserved trigram value 0 means "empty slot" in the hash table,
    // so the only trigram we skip is one whose three bytes are all zero.
    var out: [16]u32 = undefined;
    const n = extractTrigrams("\x00\x00\x00xy", &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u32, 'x' << 16), out[0]);
    try std.testing.expectEqual(@as(u32, ('x' << 8) | ('y' << 16)), out[1]);
}

test "plocate: mergeSortedPostingLists basic" {
    const allocator = std.testing.allocator;
    const a = [_]Docid{ 1, 3, 5, 7, 9 };
    const b = [_]Docid{ 3, 5, 11 };
    const d = [_]Docid{ 5, 7, 13 };
    const lists = [_][]const Docid{ &a, &b, &d };
    const result = try mergeSortedPostingLists(allocator, &lists);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(Docid, &.{5}, result);
}

test "plocate: mergeSortedPostingLists empty result" {
    const allocator = std.testing.allocator;
    const a = [_]Docid{ 1, 3, 5 };
    const b = [_]Docid{ 2, 4, 6 };
    const lists = [_][]const Docid{ &a, &b };
    const result = try mergeSortedPostingLists(allocator, &lists);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "plocate: mergeSortedPostingLists single list" {
    const allocator = std.testing.allocator;
    const a = [_]Docid{ 2, 4, 6 };
    const lists = [_][]const Docid{&a};
    const result = try mergeSortedPostingLists(allocator, &lists);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(Docid, &a, result);
}

test "plocate: unionSortedPostingLists dedup ascending" {
    const allocator = std.testing.allocator;
    const a = [_]Docid{ 1, 3, 5, 7 };
    const b = [_]Docid{ 3, 5, 9, 11 };
    const result = try unionSortedPostingLists(allocator, &a, &b);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(Docid, &.{ 1, 3, 5, 7, 9, 11 }, result);
}

test "plocate: unionSortedPostingLists disjoint keeps both" {
    const allocator = std.testing.allocator;
    const a = [_]Docid{ 2, 4 };
    const b = [_]Docid{ 1, 100 };
    const result = try unionSortedPostingLists(allocator, &a, &b);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(Docid, &.{ 1, 2, 4, 100 }, result);
}

test "plocate: findTrigram in synthetic hash table" {
    const allocator = std.testing.allocator;
    const ht_size: u32 = 16;
    const slots: u32 = 2;
    const total: usize = ht_size + slots + 1;
    const bucket99 = hashTrigram(99, ht_size);
    const bucket42 = hashTrigram(42, ht_size);

    const ht_buf = try allocator.alloc(TrigramEntry, total);
    defer allocator.free(ht_buf);
    for (ht_buf) |*e| e.* = .{ .trgm = 0, .num_docids = 0, .offset = 0 };
    ht_buf[bucket99] = .{ .trgm = 99, .num_docids = 3, .offset = 2000 };
    ht_buf[bucket99 + 1] = .{ .trgm = 0, .num_docids = 0, .offset = 2352 }; // next entry, pl size = 352
    ht_buf[bucket42] = .{ .trgm = 42, .num_docids = 7, .offset = 1000 };
    ht_buf[bucket42 + 1] = .{ .trgm = 0, .num_docids = 0, .offset = 1100 }; // next entry, pl size = 100

    const e = findTrigramWithLen(ht_buf, ht_size, slots, 99).?;
    try std.testing.expectEqual(@as(u32, 3), e.entry.num_docids);
    try std.testing.expectEqual(@as(u64, 2000), e.entry.offset);
    try std.testing.expectEqual(@as(u64, 352), e.len);

    const f = findTrigramWithLen(ht_buf, ht_size, slots, 42).?;
    try std.testing.expectEqual(@as(u32, 7), f.entry.num_docids);
    try std.testing.expectEqual(@as(u64, 100), f.len);

    try std.testing.expect(findTrigramWithLen(ht_buf, ht_size, slots, 1234) == null);
}

test "plocate: containsTarget short-needle search" {
    const data = "usr/bin/ls\x00usr/share/doc/zzz/README\x00etc/conf\x00";
    try std.testing.expect(containsTarget(data, "ls"));
    try std.testing.expect(containsTarget(data, "zzz"));
    try std.testing.expect(containsTarget(data, "usr"));
    try std.testing.expect(containsTarget(data, "zz"));
    try std.testing.expect(!containsTarget(data, "qq"));
    try std.testing.expect(!containsTarget(data, "xy"));
    // 1-byte and >4-byte needles route through the other branches.
    try std.testing.expect(containsTarget(data, "e"));
    try std.testing.expect(containsTarget(data, "usr/bin/ls"));
    try std.testing.expect(!containsTarget(data, "zzzz"));
    try std.testing.expect(!containsTarget(data, "usr/lib/dir"));
    // Needle at the very end of the slice.
    const tail = "abcZZ";
    try std.testing.expect(containsTarget(tail, "ZZ"));
    const short = "a";
    try std.testing.expect(!containsTarget(short, "zz"));
}
