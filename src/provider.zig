//! Provider abstraction: comptime-dispatched info producers.

const std = @import("std");

/// Context passed to every provider.
pub const Context = struct {
    gpa: std.mem.Allocator,
    path: []const u8,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
};

/// A single piece of info produced by a provider.
pub const Fact = struct {
    key: []const u8,
    value: []const u8,
    /// Provider that created this fact (for grouping in output).
    group: []const u8,
};

/// A provider function. Returns facts about a file.
/// Caller owns returned memory (allocated by ctx.gpa).
pub const RunFn = *const fn (ctx: Context) anyerror![]Fact;

/// A named provider.
pub const Provider = struct {
    name: []const u8,
    run: RunFn,
};