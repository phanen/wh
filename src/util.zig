//! Shared utility functions used across multiple modules.

const std = @import("std");
const builtin = @import("builtin");

pub fn cstr(s: []const u8) []const u8 {
    return std.mem.sliceTo(s, 0);
}

pub fn pathBaseMatches(path: []const u8, name: []const u8) bool {
    // NOTE: kept in sync with `plocate/src/util.zig::pathBaseMatches`.
    // The two implementations live in separate packages with no shared code,
    // so any behavior change here must be mirrored in plocate manually.
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return false;
    return std.mem.eql(u8, path[slash + 1 ..], name);
}

pub fn fileContains(target: []const u8, data: []const u8) bool {
    return matchFind(target, data) != null;
}

pub fn parseDescField(data: []const u8, key: []const u8, allocator: std.mem.Allocator) ?[]u8 {
    var lines = std.mem.splitScalar(u8, data, '\n');
    var current_key: ?[]const u8 = null;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len >= 2 and trimmed[0] == '%' and trimmed[trimmed.len - 1] == '%') {
            const inner = trimmed[1 .. trimmed.len - 1];
            current_key = if (std.mem.eql(u8, inner, key)) inner else null;
            continue;
        }
        if (current_key != null and trimmed.len > 0) {
            return allocator.dupe(u8, trimmed) catch null;
        }
    }
    return null;
}

pub fn fileExists(path: []const u8) bool {
    if (builtin.os.tag != .linux) return false;
    const linux = std.os.linux;
    const path_z = std.posix.toPosixPath(path) catch return false;
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(linux.AT.FDCWD, &path_z, 0, .{ .MODE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return false;
    return (stx.mode & linux.S.IFMT) == linux.S.IFREG;
}

pub fn matchFind(target: []const u8, data: []const u8) ?[]const u8 {
    const bare = std.mem.indexOfScalar(u8, target, '/') == null;
    var lines = std.mem.splitScalar(u8, data, '\n');
    var in_files = false;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len >= 2 and trimmed[0] == '%' and trimmed[trimmed.len - 1] == '%') {
            in_files = std.mem.eql(u8, trimmed, "%FILES%");
            continue;
        }
        if (in_files and trimmed.len > 0) {
            if (std.mem.eql(u8, trimmed, target)) return trimmed;
            if (bare and pathBaseMatches(trimmed, target)) return trimmed;
        }
    }
    return null;
}

/// Resolve symlinks via libc realpath(3), then strip the leading slash so the
/// result is a path relative to root (matching how pacman DBs store files).
/// On failure (file not found etc.) falls back to a plain strip, so callers
/// can still try pacman -F style lookups for missing files.
pub fn realpathNormalize(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (builtin.os.tag == .linux) {
        var buf: [std.c.PATH_MAX]u8 = undefined;
        const path_z = std.posix.toPosixPath(path) catch {
            return stripLeadingSlash(allocator, path);
        };
        if (std.c.realpath(&path_z, &buf)) |resolved| {
            const slice = std.mem.sliceTo(resolved, 0);
            return stripLeadingSlash(allocator, slice);
        }
    }
    return stripLeadingSlash(allocator, path);
}

fn stripLeadingSlash(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var p: []const u8 = path;
    if (p.len > 0 and p[0] == '/') p = p[1..];
    return allocator.dupe(u8, p);
}

test "realpathNormalize resolves existing absolute path" {
    const allocator = std.testing.allocator;
    const p = try realpathNormalize(allocator, "/usr/bin/ls");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("usr/bin/ls", p);
}

test "realpathNormalize resolves symlink to canonical target" {
    const allocator = std.testing.allocator;
    const p = try realpathNormalize(allocator, "/bin/ls");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("usr/bin/ls", p);
}

test "realpathNormalize falls back to strip when path missing" {
    const allocator = std.testing.allocator;
    const p = try realpathNormalize(allocator, "/nonexistent/path/does/not/exist");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("nonexistent/path/does/not/exist", p);
}

test "realpathNormalize strips slash on relative path fallback" {
    const allocator = std.testing.allocator;
    const p = try realpathNormalize(allocator, "/relative/looking");
    defer allocator.free(p);
    try std.testing.expectEqualStrings("relative/looking", p);
}
