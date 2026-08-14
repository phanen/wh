//! Unified pacman ownership provider. Combines local DB and repo DB results.
//! `[installed]` is shown on every match whose package is installed locally,
//! not only the one that owns the queried file. The local DB fallback exists
//! because repo DBs may be stale or lack the file entirely.

const std = @import("std");
const provider = @import("../provider.zig");
const pacdb = @import("pacman/pacdb.zig");
const pacfiles = @import("pacman/pacfiles.zig");
const pacrepo = @import("pacman/pacrepo.zig");
const plocate = @import("plocate");
const util = @import("../util.zig");

const Context = provider.Context;
const Fact = provider.Fact;
const fkey = provider.fact_key;

const pacman_local_dir = "/var/lib/pacman/local";

fn getInstalledPkgs(gpa: std.mem.Allocator, io: std.Io) !std.ArrayList([]const u8) {
    var pkgs: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (pkgs.items) |p| gpa.free(p);
        pkgs.deinit(gpa);
    }

    var local_dir = std.Io.Dir.openDirAbsolute(io, pacman_local_dir, .{ .iterate = true }) catch return pkgs;
    defer local_dir.close(io);

    var iter = local_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const split = pacdb.splitPkgDirName(entry.name);
        try pkgs.append(gpa, try gpa.dupe(u8, split.name));
    }

    return pkgs;
}

fn isInstalled(installed: *const std.ArrayList([]const u8), name: []const u8) bool {
    for (installed.items) |p| {
        if (std.mem.eql(u8, p, name)) return true;
    }
    return false;
}

pub fn run(ctx: Context) ![]Fact {
    const normalized = try util.realpathNormalize(ctx.gpa, ctx.path);
    defer ctx.gpa.free(normalized);

    const norm_ctx: Context = .{
        .gpa = ctx.gpa,
        .path = normalized,
        .io = ctx.io,
        .environ_map = ctx.environ_map,
    };

    var result: std.ArrayList(Fact) = .empty;
    errdefer provider.deinitFacts(ctx.gpa, &result);

    const local = try pacdb.run(norm_ctx);
    defer if (local) |p| p.free(ctx.gpa);

    var installed_pkgs = try getInstalledPkgs(ctx.gpa, ctx.io);
    defer {
        for (installed_pkgs.items) |p| ctx.gpa.free(p);
        installed_pkgs.deinit(ctx.gpa);
    }

    // Bare-name queries skip the local fallback: the pacdb basename scan costs
    // a full local DB walk and returns an arbitrary first match.
    const is_explicit_path = std.mem.indexOfScalar(u8, ctx.path, '/') != null;

    if (plocate.dbsExist(ctx.io)) {
        const matches = try pacfiles.run(norm_ctx);
        defer plocate.freeMatches(matches, ctx.gpa);
        try appendLocalFallback(ctx.gpa, &result, local, is_explicit_path, matches, "pkgname");
        for (matches) |m| {
            try appendMatch(ctx.gpa, &result, m.repo, m.pkgname, m.version, m.filepath, isInstalled(&installed_pkgs, m.pkgname));
        }
    } else {
        const matches = try pacrepo.run(norm_ctx);
        defer freeRepoMatches(ctx.gpa, matches);
        try appendLocalFallback(ctx.gpa, &result, local, is_explicit_path, matches, "name");
        for (matches) |m| {
            try appendMatch(ctx.gpa, &result, m.repo, m.name, m.version, m.filepath, isInstalled(&installed_pkgs, m.name));
        }
    }

    return try result.toOwnedSlice(ctx.gpa);
}

fn freeRepoMatches(gpa: std.mem.Allocator, matches: []const pacrepo.PkgMatch) void {
    for (matches) |m| m.free(gpa);
    gpa.free(matches);
}

fn appendLocalFallback(
    gpa: std.mem.Allocator,
    result: *std.ArrayList(Fact),
    local: ?pacdb.LocalPkg,
    is_explicit_path: bool,
    matches: anytype,
    comptime name_field: []const u8,
) !void {
    if (!is_explicit_path) return;
    const p = local orelse return;
    for (matches) |m| {
        if (std.mem.eql(u8, @field(m, name_field), p.name)) return;
    }
    try appendMatch(gpa, result, "local", p.name, p.version, p.filepath, true);
}

fn appendMatch(
    gpa: std.mem.Allocator,
    result: *std.ArrayList(Fact),
    repo: []const u8,
    name: []const u8,
    version: []const u8,
    filepath: []const u8,
    installed: bool,
) !void {
    const pkg_value = if (installed)
        try std.fmt.allocPrint(gpa, "{s}/{s} {s} [installed] {s}", .{ repo, name, version, filepath })
    else
        try std.fmt.allocPrint(gpa, "{s}/{s} {s} {s}", .{ repo, name, version, filepath });
    errdefer gpa.free(pkg_value);
    try result.append(gpa, .{
        .key = try gpa.dupe(u8, fkey.pkg),
        .value = pkg_value,
    });
}
