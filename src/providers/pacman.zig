//! Unified pacman ownership provider.
//!
//! Queries local DB (installed status) and repo DB (pacfiles/pacrepo) together.
//! Returns one Pkg fact per matching package; the pacman filepath is appended
//! to the Pkg value so it renders on the same line.
//!
//! Result policy: repo DB results are the primary display, annotated with
//! `[installed]` when the local DB names the same package. The local DB is
//! authoritative only as a fallback: it is emitted for explicit paths when no
//! repo result already names the installed package, because repo DBs may be
//! stale or lack the file entirely (the pacdb query can never be skipped).

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

/// True iff the locally-installed package has this name. At most one package
/// owns a file, so the installed status is a single bit.
fn isInstalled(local: ?pacdb.LocalPkg, name: []const u8) bool {
    return if (local) |p| std.mem.eql(u8, p.name, name) else false;
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

    // Bare-name queries skip the local fallback: the pacdb basename scan costs
    // a full local DB walk and returns an arbitrary first match.
    const is_explicit_path = std.mem.indexOfScalar(u8, ctx.path, '/') != null;

    if (plocate.dbsExist(ctx.io)) {
        const matches = try pacfiles.run(norm_ctx);
        defer plocate.freeMatches(matches, ctx.gpa);
        try appendLocalFallback(ctx.gpa, &result, local, is_explicit_path, matches, "pkgname");
        for (matches) |m| {
            try appendMatch(ctx.gpa, &result, m.repo, m.pkgname, m.version, m.filepath, isInstalled(local, m.pkgname));
        }
    } else {
        const matches = try pacrepo.run(norm_ctx);
        defer freeRepoMatches(ctx.gpa, matches);
        try appendLocalFallback(ctx.gpa, &result, local, is_explicit_path, matches, "name");
        for (matches) |m| {
            try appendMatch(ctx.gpa, &result, m.repo, m.name, m.version, m.filepath, isInstalled(local, m.name));
        }
    }

    return try result.toOwnedSlice(ctx.gpa);
}

fn freeRepoMatches(gpa: std.mem.Allocator, matches: []const pacrepo.PkgMatch) void {
    for (matches) |m| m.free(gpa);
    gpa.free(matches);
}

/// Emits the installed DB result as a fallback line, unless a repo result
/// already names the same package (that line then carries the `[installed]`
/// marker and printing the local DB again would duplicate the fact).
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
