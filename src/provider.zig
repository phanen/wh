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

/// Canonical fact keys. Providers and output consumers MUST use these
/// constants so renames/refactors stay in sync.
pub const fact_key = struct {
    pub const stat: []const u8 = "Stat";
    pub const elf: []const u8 = "ELF";
    pub const interpreter: []const u8 = "Interpreter";
    pub const deps: []const u8 = "Deps";
    pub const pkg: []const u8 = "Pkg";
    pub const magic: []const u8 = "Magic";
};

pub const RunFn = *const fn (ctx: Context) anyerror![]Fact;

pub const Provider = struct {
    name: []const u8,
    run: RunFn,
};

/// Free every fact's key/value (gpa-allocated) and then deinit the list.
/// Intended for `errdefer` cleanup of an owned `ArrayList(Fact)` whose
/// allocation semantics are: key and value are dupe/allocPrint'd with gpa.
pub fn deinitFacts(gpa: std.mem.Allocator, facts: *std.ArrayList(Fact)) void {
    for (facts.items) |f| {
        gpa.free(f.key);
        gpa.free(f.value);
    }
    facts.deinit(gpa);
}
