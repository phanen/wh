//! PATH and library path search.

const std = @import("std");
const util = @import("util.zig");

pub const FindOptions = struct {
    search_all: bool = false,
    search_libs: bool = false,
};

pub const Match = struct {
    path: []const u8,
    from_binary: bool = false,
};

const library_paths = [_][]const u8{
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
};

pub fn findBinary(
    arena: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    name: []const u8,
    options: FindOptions,
) ![]Match {
    var results: std.ArrayList(Match) = .empty;

    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        if (linuxIsExecutable(name)) {
            const path = try arena.dupe(u8, name);
            try results.append(arena, .{ .path = path, .from_binary = true });
        }
        return results.items;
    }

    const path_value = environ_map.get("PATH") orelse "";

    // tokenizeScalar skips empty components, which is the security-relevant
    // behavior: an empty PATH element must not resolve to cwd (POSIX deviation).
    var it = std.mem.tokenizeScalar(u8, path_value, std.fs.path.delimiter);
    while (it.next()) |dir| {
        const full = try std.fs.path.join(arena, &.{ dir, name });
        if (linuxIsExecutable(full)) {
            try results.append(arena, .{ .path = full, .from_binary = true });
            if (!options.search_all) return results.items;
        }
    }

    return results.items;
}

pub fn find(
    arena: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    name: []const u8,
    options: FindOptions,
) ![]Match {
    if (std.mem.indexOfScalar(u8, name, '/') != null) {
        if (util.fileExists(name) or isSymlink(name)) {
            var r: std.ArrayList(Match) = .empty;
            try r.append(arena, .{ .path = try arena.dupe(u8, name) });
            return r.items;
        }
        return arena.dupe(Match, &.{});
    }

    // -l: library paths only.
    if (options.search_libs) {
        return findLibrary(arena, environ_map, name, .{ .search_all = options.search_all });
    }

    // -a: search both, dedup by realpath (merged symlink dirs).
    if (options.search_all) {
        var results: std.ArrayList(Match) = .empty;
        var seen: std.ArrayList([]const u8) = .empty;
        const bin = try findBinary(arena, environ_map, name, .{ .search_all = true });
        for (bin) |m| try appendUnique(arena, &results, &seen, m);
        const lib = try findLibrary(arena, environ_map, name, .{ .search_all = true });
        for (lib) |m| try appendUnique(arena, &results, &seen, m);
        return results.items;
    }

    // Default: PATH first, fall back to library paths.
    const bin = try findBinary(arena, environ_map, name, .{ .search_all = false });
    if (bin.len > 0) return bin;
    return findLibrary(arena, environ_map, name, .{ .search_all = false });
}

fn appendUnique(
    arena: std.mem.Allocator,
    results: *std.ArrayList(Match),
    seen: *std.ArrayList([]const u8),
    m: Match,
) !void {
    const rp = canonicalize(arena, m.path);
    for (seen.items) |s| {
        if (std.mem.eql(u8, s, rp)) return;
    }
    try seen.append(arena, rp);
    try results.append(arena, m);
}

fn canonicalize(arena: std.mem.Allocator, path: []const u8) []const u8 {
    var buf: [std.c.PATH_MAX]u8 = undefined;
    const path_z = std.posix.toPosixPath(path) catch return path;
    const resolved = std.c.realpath(&path_z, &buf) orelse return path;
    const slice = std.mem.sliceTo(resolved, 0);
    return arena.dupe(u8, slice) catch return path;
}

fn isSymlink(path: []const u8) bool {
    const linux = std.os.linux;
    const path_z = std.posix.toPosixPath(path) catch return false;
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        &path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true },
        &stx,
    );
    if (rc != 0) return false;
    return (stx.mode & linux.S.IFMT) == linux.S.IFLNK;
}

pub fn findLibrary(
    arena: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    name: []const u8,
    options: FindOptions,
) ![]Match {
    var results: std.ArrayList(Match) = .empty;

    var search_dirs: std.ArrayList([]const u8) = .empty;
    defer search_dirs.deinit(arena);

    const ld_path = environ_map.get("LD_LIBRARY_PATH") orelse "";
    var it = std.mem.tokenizeScalar(u8, ld_path, std.fs.path.delimiter);
    while (it.next()) |dir| {
        try search_dirs.append(arena, dir);
    }
    for (library_paths) |dir| {
        try search_dirs.append(arena, dir);
    }

    const name_with_so = try std.mem.concat(arena, u8, &.{ "lib", name, ".so" });
    const name_with_a = try std.mem.concat(arena, u8, &.{ "lib", name, ".a" });
    const bare_so = std.mem.startsWith(u8, name, "lib") and std.mem.endsWith(u8, name, ".so");
    var candidates: std.ArrayList([]const u8) = .empty;
    defer candidates.deinit(arena);
    try candidates.append(arena, name);
    try candidates.append(arena, name_with_so);
    try candidates.append(arena, name_with_a);
    if (!bare_so) {
        try candidates.append(arena, try std.mem.concat(arena, u8, &.{ name, ".so" }));
    }

    for (search_dirs.items) |dir| {
        for (candidates.items) |cand| {
            const full = try std.fs.path.join(arena, &.{ dir, cand });
            if (util.fileExists(full)) {
                try results.append(arena, .{ .path = full });
                if (!options.search_all) return results.items;
            }
        }
    }

    return results.items;
}

fn statxMode(path: []const u8) ?u16 {
    const linux = std.os.linux;
    var buf: linux.Statx = std.mem.zeroes(linux.Statx);
    const path_z = std.posix.toPosixPath(path) catch return null;
    const rc = linux.statx(
        linux.AT.FDCWD,
        &path_z,
        0,
        .{ .TYPE = true, .MODE = true },
        &buf,
    );
    if (rc != 0) return null;
    return buf.mode;
}

fn linuxIsExecutable(path: []const u8) bool {
    const mode = statxMode(path) orelse return false;
    const type_mask: u16 = mode & std.os.linux.S.IFMT;
    if (type_mask != std.os.linux.S.IFREG) return false;
    const exec_bits: u16 = std.os.linux.S.IXUSR | std.os.linux.S.IXGRP | std.os.linux.S.IXOTH;
    return (mode & exec_bits) != 0;
}
