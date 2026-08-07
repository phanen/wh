//! wh - enhanced which/ldd replacement
pub const util = @import("util.zig");
pub const discover = @import("discover.zig");
pub const provider = @import("provider.zig");
pub const output = @import("output.zig");
pub const file_meta = @import("providers/file_meta.zig");
pub const elf_parse = @import("elf_parse.zig");
pub const ld_cache = @import("ld_cache.zig");
pub const elf_info = @import("providers/elf_info.zig");
pub const elf_deps = @import("providers/elf_deps.zig");
pub const pacdb = @import("providers/pacdb.zig");
pub const pacrepo = @import("providers/pacrepo.zig");
pub const pacfiles = @import("providers/pacfiles.zig");
pub const pacman = @import("providers/pacman.zig");
pub const plocate = @import("plocate.zig");

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
    _ = pacdb;
    _ = pacrepo;
    _ = pacfiles;
    _ = pacman;
    _ = plocate;
}