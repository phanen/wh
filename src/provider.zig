//! Provider abstraction: comptime-dispatched info producers.

const std = @import("std");

pub const Context = struct {
    gpa: std.mem.Allocator,
    path: []const u8,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
};

pub const Fact = struct {
    key: []const u8,
    value: []const u8,
};

pub const RunFn = *const fn (ctx: Context) anyerror![]Fact;

pub const Provider = struct {
    name: []const u8,
    run: RunFn,
};