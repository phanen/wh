//! Pacfiles provider.

const std = @import("std");
const provider = @import("../provider.zig");
const plocate = @import("../plocate.zig");
const Context = provider.Context;

pub fn run(ctx: Context) ![]plocate.PacfilesMatch {
    const results = plocate.search(ctx.gpa, ctx.io, ctx.path) catch |err| {
        std.log.warn("pacfiles: search failed: {s}", .{@errorName(err)});
        return try ctx.gpa.alloc(plocate.PacfilesMatch, 0);
    };
    return results;
}