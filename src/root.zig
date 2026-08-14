//! wh - enhanced which/ldd replacement
const std = @import("std");

pub const util = @import("util.zig");
pub const discover = @import("discover.zig");
pub const provider = @import("provider.zig");
pub const output = @import("output.zig");
pub const file_meta = @import("providers/file_meta.zig");
pub const elf_parse = @import("elf_parse.zig");
pub const ld_cache = @import("ld_cache.zig");
pub const elf_info = @import("providers/elf_info.zig");
pub const elf_deps = @import("providers/elf_deps.zig");
pub const magic_info = @import("providers/magic_info.zig");
pub const pacdb = @import("providers/pacman/pacdb.zig");
pub const pacrepo = @import("providers/pacman/pacrepo.zig");
pub const pacfiles = @import("providers/pacman/pacfiles.zig");
pub const pacman = @import("providers/pacman.zig");
pub const plocate = @import("plocate");

// The codebase uses @intCast(u64 -> usize) extensively (e.g. ELF section
// offsets, file sizes). 32-bit targets would silently truncate these values
// and risk out-of-bounds reads. Pin to 64-bit only and assert at compile time.
comptime {
    std.debug.assert(@sizeOf(usize) == 8);
}

test "root module" {
    _ = util;
    _ = discover;
    _ = provider;
    _ = output;
    _ = file_meta;
    _ = elf_parse;
    _ = ld_cache;
    _ = elf_info;
    _ = elf_deps;
    _ = magic_info;
    _ = pacdb;
    _ = pacrepo;
    _ = pacfiles;
    _ = pacman;
    _ = plocate;
}
