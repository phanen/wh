//! ELF dependency resolution provider (ldd replacement).

const std = @import("std");
const builtin = @import("builtin");
const util = @import("../util.zig");
const provider = @import("../provider.zig");
const elf_parse = @import("../elf_parse.zig");
const ld_cache = @import("../ld_cache.zig");
const Context = provider.Context;
const Fact = provider.Fact;
const key = provider.fact_key;

const system_paths = [_][]const u8{
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
};

pub fn run(ctx: Context) ![]Fact {
    var facts: std.ArrayList(Fact) = .empty;
    errdefer provider.deinitFacts(ctx.gpa, &facts);

    var parsed = elf_parse.parseFile(ctx.gpa, ctx.io, ctx.path) catch
        return try facts.toOwnedSlice(ctx.gpa);
    defer parsed.deinit(ctx.gpa);

    const needed = try parsed.getNeeded(ctx.gpa);
    defer {
        for (needed) |n| ctx.gpa.free(n);
        ctx.gpa.free(needed);
    }

    const rpath = parsed.getRpath();
    const runpath = parsed.getRunpath();

    var cache: ld_cache.LDCache = undefined;
    var cache_loaded = false;
    defer if (cache_loaded) cache.deinit(ctx.gpa);
    if (ld_cache.LDCache.load(ctx.gpa, ctx.io)) |c| {
        cache = c;
        cache_loaded = true;
    } else |_| {
        // Ignore cache failures; we still have default paths.
    }

    var value_buf: std.ArrayList(u8) = .empty;
    errdefer value_buf.deinit(ctx.gpa);

    for (needed) |soname| {
        const resolved = resolveSoname(ctx, soname, rpath, runpath, if (cache_loaded) &cache else null);
        const path_str = describeDep(soname, resolved.path);
        if (value_buf.items.len > 0) try value_buf.append(ctx.gpa, '\n');
        try value_buf.appendSlice(ctx.gpa, soname);
        try value_buf.appendSlice(ctx.gpa, " => ");
        try value_buf.appendSlice(ctx.gpa, path_str);
        if (resolved.must_free) ctx.gpa.free(resolved.path);
    }

    if (value_buf.items.len == 0) return try facts.toOwnedSlice(ctx.gpa);

    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, key.deps),
        .value = try value_buf.toOwnedSlice(ctx.gpa),
    });

    return try facts.toOwnedSlice(ctx.gpa);
}

fn describeDep(soname: []const u8, path: []const u8) []const u8 {
    if (std.mem.indexOf(u8, soname, "vdso") != null and std.mem.eql(u8, path, "not found"))
        return "(vdso)";
    return path;
}

const ResolvedPath = struct {
    path: []const u8,
    must_free: bool,
};

fn resolveSoname(
    ctx: Context,
    soname: []const u8,
    rpath: ?[]const u8,
    runpath: ?[]const u8,
    cache_opt: ?*const ld_cache.LDCache,
) ResolvedPath {
    if (std.mem.indexOfScalar(u8, soname, '/') != null) {
        if (util.fileExists(soname)) return .{ .path = soname, .must_free = false };
        return .{ .path = "not found", .must_free = false };
    }

    // $ORIGIN expands to the directory of the binary being analyzed.
    const binary_dir = std.fs.path.dirname(ctx.path) orelse ".";

    if (runpath) |rp| {
        const expanded = expandTokens(ctx.gpa, rp, binary_dir) catch rp;
        const need_free = expanded.ptr != rp.ptr;
        defer if (need_free) ctx.gpa.free(expanded);
        if (trySearchDirs(ctx, soname, expanded)) |p| return .{ .path = p, .must_free = true };
    } else if (rpath) |rp| {
        const expanded = expandTokens(ctx.gpa, rp, binary_dir) catch rp;
        const need_free = expanded.ptr != rp.ptr;
        defer if (need_free) ctx.gpa.free(expanded);
        if (trySearchDirs(ctx, soname, expanded)) |p| return .{ .path = p, .must_free = true };
    }

    if (ctx.environ_map.get("LD_LIBRARY_PATH")) |ld_path| {
        if (trySearchDirs(ctx, soname, ld_path)) |p| return .{ .path = p, .must_free = true };
    }

    if (cache_opt) |cache| {
        if (cache.lookup(soname)) |p| return .{ .path = p, .must_free = false };
    }

    for (system_paths) |dir| {
        const full = std.fs.path.join(ctx.gpa, &.{ dir, soname }) catch continue;
        if (util.fileExists(full)) return .{ .path = full, .must_free = true };
        ctx.gpa.free(full);
    }

    return .{ .path = "not found", .must_free = false };
}

fn expandTokens(
    allocator: std.mem.Allocator,
    input: []const u8,
    origin: []const u8,
) ![]const u8 {
    const has_origin = std.mem.indexOf(u8, input, "$ORIGIN") != null or
        std.mem.indexOf(u8, input, "${ORIGIN}") != null;
    const has_lib = std.mem.indexOf(u8, input, "$LIB") != null or
        std.mem.indexOf(u8, input, "${LIB}") != null;
    if (!has_origin and !has_lib) return @constCast(input);

    const is_64 = switch (builtin.cpu.arch) {
        .x86_64, .aarch64, .powerpc64le, .s390x, .riscv64, .mips64 => true,
        else => false,
    };
    const lib_str: []const u8 = if (is_64) "lib64" else "lib";

    var result = try std.ArrayList(u8).initCapacity(allocator, input.len);
    var rest = input;
    while (true) {
        if (std.mem.indexOf(u8, rest, "$ORIGIN")) |pos| {
            try result.appendSlice(allocator, rest[0..pos]);
            try result.appendSlice(allocator, origin);
            rest = rest[pos + 7 ..];
            continue;
        }
        if (std.mem.indexOf(u8, rest, "${ORIGIN}")) |pos| {
            try result.appendSlice(allocator, rest[0..pos]);
            try result.appendSlice(allocator, origin);
            rest = rest[pos + 10 ..];
            continue;
        }
        if (std.mem.indexOf(u8, rest, "$LIB")) |pos| {
            try result.appendSlice(allocator, rest[0..pos]);
            try result.appendSlice(allocator, lib_str);
            rest = rest[pos + 4 ..];
            continue;
        }
        if (std.mem.indexOf(u8, rest, "${LIB}")) |pos| {
            try result.appendSlice(allocator, rest[0..pos]);
            try result.appendSlice(allocator, lib_str);
            rest = rest[pos + 6 ..];
            continue;
        }
        try result.appendSlice(allocator, rest);
        break;
    }
    return try result.toOwnedSlice(allocator);
}

fn trySearchDirs(ctx: Context, soname: []const u8, dir_list: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, dir_list, ':');
    while (it.next()) |dir| {
        const full = std.fs.path.join(ctx.gpa, &.{ dir, soname }) catch continue;
        if (util.fileExists(full)) return full;
        ctx.gpa.free(full);
    }
    return null;
}

test "elf_deps: describeDep maps vDSO" {
    try std.testing.expectEqualStrings("(vdso)", describeDep("linux-vdso.so.1", "not found"));
    try std.testing.expectEqualStrings(
        "/usr/lib/libc.so.6",
        describeDep("libc.so.6", "/usr/lib/libc.so.6"),
    );
    try std.testing.expectEqualStrings("not found", describeDep("libfoo.so", "not found"));
}
