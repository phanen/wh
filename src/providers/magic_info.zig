//! libmagic file type identification provider (libmagic-backed `file`).

const std = @import("std");
const provider = @import("../provider.zig");
const Context = provider.Context;
const Fact = provider.Fact;
const key = provider.fact_key;

const MAGIC_SYMLINK: c_int = 0x0000002;

const magic_t = ?*opaque {};

extern "c" fn magic_open(flags: c_int) magic_t;
extern "c" fn magic_close(handle: magic_t) void;
extern "c" fn magic_file(handle: magic_t, path: [*:0]const u8) ?[*:0]const u8;
extern "c" fn magic_load(handle: magic_t, magic_file: ?[*:0]const u8) c_int;

pub fn run(ctx: Context) ![]Fact {
    var facts: std.ArrayList(Fact) = .empty;
    errdefer provider.deinitFacts(ctx.gpa, &facts);

    const path_z = std.posix.toPosixPath(ctx.path) catch
        return try facts.toOwnedSlice(ctx.gpa);

    const handle = magic_open(MAGIC_SYMLINK) orelse
        return try facts.toOwnedSlice(ctx.gpa);
    defer magic_close(handle);

    if (magic_load(handle, null) != 0)
        return try facts.toOwnedSlice(ctx.gpa);

    const desc_ptr = magic_file(handle, &path_z) orelse
        return try facts.toOwnedSlice(ctx.gpa);
    const desc = std.mem.span(desc_ptr);

    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, key.magic),
        .value = try ctx.gpa.dupe(u8, desc),
    });

    return try facts.toOwnedSlice(ctx.gpa);
}


