//! PATH and library path search.

const std = @import("std");

pub const FindOptions = struct {
    search_all: bool = false,
    search_libs: bool = false,
};

pub const Match = struct {
    path: []const u8,
};

/// Hardcoded library search paths (used by `-l`).
const library_paths = [_][]const u8{
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
};

/// Search for a binary in PATH directories.
///
/// If `name` contains `/`, the path is checked directly without searching PATH.
/// Otherwise each PATH component is checked with executable bits set.
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
            try results.append(arena, .{ .path = path });
        }
        return results.items;
    }

    const path_value = environ_map.get("PATH") orelse "";

    var it = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (it.next()) |dir| {
        // Security: skip empty PATH components rather than searching cwd (POSIX deviation).
        if (dir.len == 0) continue;
        const full = try std.fs.path.join(arena, &[_][]const u8{ dir, name });
        if (linuxIsExecutable(full)) {
            try results.append(arena, .{ .path = full });
            if (!options.search_all) return results.items;
        }
    }

    return results.items;
}

/// Search for a library in system library paths plus `LD_LIBRARY_PATH`.
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
    var it = std.mem.splitScalar(u8, ld_path, std.fs.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        try search_dirs.append(arena, dir);
    }
    for (library_paths) |dir| {
        try search_dirs.append(arena, dir);
    }

    const name_with_so = try std.mem.concat(arena, u8, &.{ "lib", name, ".so" });
    const name_with_a = try std.mem.concat(arena, u8, &.{ "lib", name, ".a" });
    const candidates = [_][]const u8{
        name,
        name_with_so,
        name_with_a,
    };

    for (search_dirs.items) |dir| {
        for (candidates) |cand| {
            const full = try std.fs.path.join(arena, &[_][]const u8{ dir, cand });
            if (fileExists(full)) {
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

/// Returns true if `path` is a regular file with at least one execute bit set.
fn linuxIsExecutable(path: []const u8) bool {
    const mode = statxMode(path) orelse return false;
    const type_mask: u16 = mode & std.os.linux.S.IFMT;
    if (type_mask != std.os.linux.S.IFREG) return false;
    const exec_bits: u16 = std.os.linux.S.IXUSR | std.os.linux.S.IXGRP | std.os.linux.S.IXOTH;
    return (mode & exec_bits) != 0;
}

/// Returns true if `path` exists as a regular file.
fn fileExists(path: []const u8) bool {
    const mode = statxMode(path) orelse return false;
    return (mode & std.os.linux.S.IFMT) == std.os.linux.S.IFREG;
}
