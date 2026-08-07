const std = @import("std");
const Io = std.Io;
const wh = @import("wh");

const discover = wh.discover;
const provider = wh.provider;
const output = wh.output;
const util = wh.util;
const file_meta = wh.file_meta;
const elf_info = wh.elf_info;
const elf_deps = wh.elf_deps;
const pacman = wh.pacman;

const AlwaysProviders = [_]provider.Provider{
    .{ .name = "file_meta", .run = file_meta.run },
    .{ .name = "elf_info", .run = elf_info.run },
    .{ .name = "elf_deps", .run = elf_deps.run },
};

const version_str = "wh 0.1.0";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const environ_map = init.environ_map;

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;

    const stdout_file: Io.File = .stdout();
    var stdout_file_writer: Io.File.Writer = .init(stdout_file, io, &stdout_buf);
    const stdout_w = &stdout_file_writer.interface;
    defer stdout_w.flush() catch {};

    const stderr_file: Io.File = .stderr();
    var stderr_file_writer: Io.File.Writer = .init(stderr_file, io, &stderr_buf);
    const stderr_w = &stderr_file_writer.interface;
    defer stderr_w.flush() catch {};

    const style = output.detectStyle(io, stdout_file, environ_map);

    const parse = parseArgs(args[1..], arena) catch |err| {
        try output.printError(stderr_w, style, @errorName(err));
        try printUsage(stderr_w);
        std.process.exit(1);
    };

    if (parse.show_help) {
        try printUsage(stdout_w);
        return;
    }
    if (parse.show_version) {
        try stdout_w.writeAll(version_str ++ "\n");
        return;
    }

    if (parse.targets.len == 0) {
        try printUsage(stderr_w);
        std.process.exit(1);
    }

    var found_any = false;

    for (parse.targets) |target| {
        const matches = try discover.find(arena, environ_map, target, parse.options);

        if (matches.len == 0) {
            const ctx: provider.Context = .{
                .gpa = gpa,
                .path = target,
                .io = io,
                .environ_map = environ_map,
            };
            const facts = pacman.run(ctx) catch |err| blk: {
                try output.printError(stderr_w, style, @errorName(err));
                break :blk try gpa.alloc(provider.Fact, 0);
            };
            if (facts.len > 0) {
                try output.printName(stdout_w, style, target, null);
                for (facts) |f| try output.printFact(stdout_w, style, f);
                found_any = true;
            } else {
                try stderr_w.writeAll("error: not found: ");
                try stderr_w.writeAll(target);
                try stderr_w.writeAll("\n");
                stderr_w.flush() catch {};
            }
            for (facts) |f| {
                gpa.free(f.key);
                gpa.free(f.value);
            }
            gpa.free(facts);
            continue;
        }

        found_any = true;

        for (matches, 0..) |m, i| {
            if (i > 0) try stdout_w.writeByte('\n');

            const symlink = symlinkTarget(gpa, io, m.path);
            defer if (symlink) |s| gpa.free(s);
            try output.printName(stdout_w, style, m.path, symlink);

            for (AlwaysProviders) |p| {
                const ctx: provider.Context = .{
                    .gpa = gpa,
                    .path = m.path,
                    .io = io,
                    .environ_map = environ_map,
                };
                const facts = p.run(ctx) catch |err| {
                    try output.printError(stderr_w, style, @errorName(err));
                    continue;
                };
                defer {
                    for (facts) |f| {
                        gpa.free(f.key);
                        gpa.free(f.value);
                    }
                    gpa.free(facts);
                }
                for (facts) |f| try output.printFact(stdout_w, style, f);
            }

            const ctx: provider.Context = .{
                .gpa = gpa,
                .path = m.path,
                .io = io,
                .environ_map = environ_map,
            };
            const facts = pacman.run(ctx) catch |err| blk: {
                try output.printError(stderr_w, style, @errorName(err));
                break :blk try gpa.alloc(provider.Fact, 0);
            };
            defer {
                for (facts) |f| {
                    gpa.free(f.key);
                    gpa.free(f.value);
                }
                gpa.free(facts);
            }
            for (facts) |f| try output.printFact(stdout_w, style, f);
        }

        const has_binary = for (matches) |m| {
            if (m.from_binary) break true;
        } else false;
        const is_bare_name = std.mem.indexOfScalar(u8, target, '/') == null;
        const do_dual_query = !parse.options.search_libs
            and is_bare_name
            and (parse.options.search_all or !has_binary);
        if (do_dual_query) {
            const ctx2: provider.Context = .{
                .gpa = gpa,
                .path = target,
                .io = io,
                .environ_map = environ_map,
            };
            const facts2 = pacman.run(ctx2) catch |err| blk: {
                try output.printError(stderr_w, style, @errorName(err));
                break :blk try gpa.alloc(provider.Fact, 0);
            };
            defer {
                for (facts2) |f| {
                    gpa.free(f.key);
                    gpa.free(f.value);
                }
                gpa.free(facts2);
            }
            if (facts2.len > 0) {
                try stdout_w.writeByte('\n');
                try output.printName(stdout_w, style, target, null);
                for (facts2) |f| try output.printFact(stdout_w, style, f);
            }
        }
    }

    if (!found_any) {
        stdout_w.flush() catch {};
        stderr_w.flush() catch {};
        std.process.exit(1);
    }
}

const ParseResult = struct {
    options: discover.FindOptions = .{},
    show_help: bool = false,
    show_version: bool = false,
    targets: []const []const u8 = &.{},
    targets_list: std.ArrayList([]const u8) = .empty,
};

const ParseError = error{
    UnknownFlag,
    MissingValue,
};

fn parseArgs(args: []const []const u8, arena: std.mem.Allocator) !ParseResult {
    var result: ParseResult = .{};
    var targets: std.ArrayList([]const u8) = .empty;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (arg.len == 0) continue;
        if (arg[0] != '-') {
            try targets.append(arena, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) {
                try targets.append(arena, args[i]);
            }
            break;
        }
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            result.show_help = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            result.show_version = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            result.options.search_all = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--libs")) {
            result.options.search_libs = true;
            continue;
        }
        return error.UnknownFlag;
    }

    result.targets = targets.items;
    result.targets_list = targets;
    return result;
}

/// Returns the readlink target if `path` is a symlink, otherwise null.
fn symlinkTarget(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const linux = std.os.linux;
    const path_z = std.posix.toPosixPath(path) catch return null;
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        &path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true },
        &stx,
    );
    if (rc != 0) return null;
    if ((stx.mode & linux.S.IFMT) != linux.S.IFLNK) return null;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().readLink(io, path, &buf) catch return null;
    return gpa.dupe(u8, buf[0..n]) catch null;
}

fn printUsage(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: wh [OPTIONS] NAME...
        \\
        \\Show file metadata for binaries or libraries.
        \\
        \\Options:
        \\  -a, --all       Show all matches in PATH
        \\  -l, --libs      Search library paths (-l m looks for libm.so etc.)
        \\  -h, --help      Show this help
        \\  -V, --version   Show version
        \\
    );
}

test "parseArgs handles flags" {
    const allocator = std.testing.allocator;
    var r = try parseArgs(&.{ "-a", "-l", "ls", "m" }, allocator);
    defer r.targets_list.deinit(allocator);
    try std.testing.expect(r.options.search_all);
    try std.testing.expect(r.options.search_libs);
    try std.testing.expectEqual(@as(usize, 2), r.targets.len);
}

test "parseArgs rejects unknown flag" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnknownFlag, parseArgs(&.{"-x"}, allocator));
}

test "parseArgs handles --" {
    const allocator = std.testing.allocator;
    var r = try parseArgs(&.{ "--", "-weird-name" }, allocator);
    defer r.targets_list.deinit(allocator);
    try std.testing.expectEqualStrings("-weird-name", r.targets[0]);
}