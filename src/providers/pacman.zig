//! Unified pacman ownership provider.
//!
//! Queries local DB (installed status) and repo DB (pacfiles/pacrepo) together.
//! Returns one Pkg fact per matching package; the pacman filepath is appended
//! to the Pkg value so it renders on the same line.

const std = @import("std");
const provider = @import("../provider.zig");
const pacdb = @import("pacdb.zig");
const pacfiles = @import("pacfiles.zig");
const pacrepo = @import("pacrepo.zig");
const plocate = @import("../plocate.zig");
const util = @import("../util.zig");

const Context = provider.Context;
const Fact = provider.Fact;

fn freeFacts(ctx: Context, facts: []Fact) void {
    for (facts) |f| {
        ctx.gpa.free(f.key);
        ctx.gpa.free(f.value);
    }
    ctx.gpa.free(facts);
}

fn isInstalled(local_facts: []Fact, name: []const u8) bool {
    for (local_facts) |f| {
        if (std.mem.eql(u8, f.key, "Package") and std.mem.eql(u8, f.value, name))
            return true;
    }
    return false;
}

fn extractField(facts: []Fact, key: []const u8) ?[]const u8 {
    for (facts) |f| {
        if (std.mem.eql(u8, f.key, key)) return f.value;
    }
    return null;
}

pub fn run(ctx: Context) anyerror![]Fact {
    const normalized = try util.realpathNormalize(ctx.gpa, ctx.path);
    defer ctx.gpa.free(normalized);

    const norm_ctx: Context = .{
        .gpa = ctx.gpa,
        .path = normalized,
        .io = ctx.io,
        .environ_map = ctx.environ_map,
    };

    var result: std.ArrayList(Fact) = .empty;
    errdefer {
        for (result.items) |f| {
            ctx.gpa.free(f.key);
            ctx.gpa.free(f.value);
        }
        result.deinit(ctx.gpa);
    }

    const local_facts = try pacdb.run(norm_ctx);
    defer freeFacts(norm_ctx, local_facts);

    const is_explicit_path = std.mem.indexOfScalar(u8, ctx.path, '/') != null;

    if (is_explicit_path and local_facts.len > 0) {
        for (local_facts) |f| {
            if (std.mem.eql(u8, f.key, "Package")) {
                const version = extractField(local_facts, "Version") orelse "";
                const filepath = extractField(local_facts, "FilePath") orelse normalized;
                try appendMatch(ctx.gpa, &result, "local", f.value, version, filepath, true);
                break;
            }
        }
        return try result.toOwnedSlice(ctx.gpa);
    }

    if (plocate.dbsExist(ctx.io)) {
        const matches = try pacfiles.run(norm_ctx);
        defer plocate.freeMatches(matches, ctx.gpa);
        for (matches) |m| try appendMatch(ctx.gpa, &result, m.repo, m.pkgname, m.version, m.filepath, isInstalled(local_facts, m.pkgname));
    } else {
        const matches = try pacrepo.run(norm_ctx);
        defer {
            for (matches) |m| {
                ctx.gpa.free(m.name);
                ctx.gpa.free(m.version);
                ctx.gpa.free(m.repo);
                ctx.gpa.free(m.filepath);
            }
            ctx.gpa.free(matches);
        }
        for (matches) |m| try appendMatch(ctx.gpa, &result, m.repo, m.name, m.version, m.filepath, isInstalled(local_facts, m.name));
    }

    return try result.toOwnedSlice(ctx.gpa);
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
        .key = try gpa.dupe(u8, "Pkg"),
        .value = pkg_value,
    });
}
