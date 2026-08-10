const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const plocate_mod = b.addModule("plocate", .{
        .root_source_file = b.path("src/plocate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    plocate_mod.linkSystemLibrary("zstd", .{});

    const lib_unit_tests = b.addTest(.{
        .root_module = plocate_mod,
        .use_llvm = true,
        .use_lld = true,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
