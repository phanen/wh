const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Read version from build.zig.zon so --version always matches the manifest.
    const zon_content = try b.build_root.handle.readFileAlloc(
        b.graph.io,
        "build.zig.zon",
        b.allocator,
        .limited(4096),
    );
    defer b.allocator.free(zon_content);
    const zon_content_z = try b.allocator.dupeZ(u8, zon_content);
    defer b.allocator.free(zon_content_z);
    const ZonInfo = struct { version: []const u8 };
    const zon_info = try std.zon.parse.fromSliceAlloc(ZonInfo, b.allocator, zon_content_z, null, .{ .ignore_unknown_fields = true });
    defer std.zon.parse.free(b.allocator, zon_info);
    const version = try std.SemanticVersion.parse(zon_info.version);

    const build_options = b.addOptions();
    build_options.addOption(std.SemanticVersion, "version", version);

    const plocate_dep = b.dependency("plocate", .{
        .target = target,
        .optimize = optimize,
    });
    const plocate_mod = plocate_dep.module("plocate");

    const mod = b.addModule("wh", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("plocate", plocate_mod);
    mod.addImport("build_options", build_options.createModule());

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "wh", .module = mod },
            .{ .name = "plocate", .module = plocate_mod },
            .{ .name = "build_options", .module = build_options.createModule() },
        },
    });
    exe_mod.linkSystemLibrary("zstd", .{});

    const exe = b.addExecutable(.{
        .name = "wh",
        .root_module = exe_mod,
        .use_llvm = true,
        .use_lld = true,
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run wh");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
        .use_llvm = true,
        .use_lld = true,
    });
    mod_tests.root_module.linkSystemLibrary("zstd", .{});
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .use_llvm = true,
        .use_lld = true,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const plocate_tests = b.addTest(.{
        .root_module = plocate_mod,
        .use_llvm = true,
        .use_lld = true,
    });
    plocate_tests.root_module.linkSystemLibrary("zstd", .{});
    const run_plocate_tests = b.addRunArtifact(plocate_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_plocate_tests.step);
}
