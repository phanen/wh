const build_options = @import("build_options");
const std = @import("std");
const Io = std.Io;
const wh = @import("wh");

const discover = wh.discover;
const provider = wh.provider;
const output = wh.output;
const file_meta = wh.file_meta;
const elf_info = wh.elf_info;
const elf_deps = wh.elf_deps;
const pacman = wh.pacman;

const always_providers = [_]provider.Provider{
    .{ .name = "file_meta", .run = file_meta.run },
    .{ .name = "elf_info", .run = elf_info.run },
    .{ .name = "elf_deps", .run = elf_deps.run },
};

const version_str = "wh " ++ build_options.version;

const stdout_scratch_size: usize = 4096;

const RunContext = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    style: output.Style,
    stdout_writer: *std.Io.Writer,
    stderr_writer: *std.Io.Writer,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const environ_map = init.environ_map;

    var stdout_buf: [stdout_scratch_size]u8 = undefined;
    var stderr_buf: [stdout_scratch_size]u8 = undefined;

    const stdout_file: Io.File = .stdout();
    var stdout_file_writer: Io.File.Writer = .init(stdout_file, io, &stdout_buf);
    const stdout_writer = &stdout_file_writer.interface;
    // Stdout flush failure after all prints is non-fatal; output is already in the writer.
    defer stdout_writer.flush() catch {};

    const stderr_file: Io.File = .stderr();
    var stderr_file_writer: Io.File.Writer = .init(stderr_file, io, &stderr_buf);
    const stderr_writer = &stderr_file_writer.interface;
    defer stderr_writer.flush() catch {};

    const style = output.detectStyle(io, stdout_file, environ_map);

    var run_ctx: RunContext = .{
        .gpa = gpa,
        .arena = arena,
        .io = io,
        .environ_map = environ_map,
        .style = style,
        .stdout_writer = stdout_writer,
        .stderr_writer = stderr_writer,
    };

    const parse = parseArgs(args[1..], arena) catch |err| {
        try output.printError(run_ctx.stderr_writer, run_ctx.style, @errorName(err));
        try printUsage(run_ctx.stderr_writer);
        std.process.exit(1);
    };

    if (parse.show_help) {
        try printUsage(run_ctx.stdout_writer);
        return;
    }
    if (parse.show_version) {
        try run_ctx.stdout_writer.writeAll(version_str ++ "\n");
        return;
    }

    if (parse.targets.len == 0) {
        try printUsage(run_ctx.stderr_writer);
        std.process.exit(1);
    }

    var found_any = false;
    for (parse.targets) |target| {
        const found = try processTarget(&run_ctx, target, parse.options);
        found_any = found_any or found;
    }

    if (!found_any) {
        // std.process.exit skips deferred statements, so flush stdout/stderr
        // by hand before bailing. Subsequent defer flushes are then no-ops.
        run_ctx.stdout_writer.flush() catch {};
        run_ctx.stderr_writer.flush() catch {};
        std.process.exit(1);
    }
}

fn freeFacts(gpa: std.mem.Allocator, facts: []provider.Fact) void {
    for (facts) |f| {
        gpa.free(f.key);
        gpa.free(f.value);
    }
    gpa.free(facts);
}

fn runPacmanAndPrint(
    ctx: *RunContext,
    path: []const u8,
    print_name: bool,
    print_separator: bool,
) !bool {
    const pctx: provider.Context = .{
        .gpa = ctx.gpa,
        .path = path,
        .io = ctx.io,
        .environ_map = ctx.environ_map,
    };
    const facts = pacman.run(pctx) catch |err| blk: {
        try output.printError(ctx.stderr_writer, ctx.style, @errorName(err));
        break :blk try ctx.gpa.alloc(provider.Fact, 0);
    };
    if (facts.len == 0) {
        freeFacts(ctx.gpa, facts);
        return false;
    }
    if (print_separator) try ctx.stdout_writer.writeByte('\n');
    if (print_name) try output.printName(ctx.stdout_writer, ctx.style, path, null);
    for (facts) |f| try output.printFact(ctx.stdout_writer, ctx.style, f);
    freeFacts(ctx.gpa, facts);
    return true;
}

fn processTarget(
    ctx: *RunContext,
    target: []const u8,
    opts: discover.FindOptions,
) !bool {
    const is_explicit_path = std.mem.indexOfScalar(u8, target, '/') != null;

    const matches = try discover.find(ctx.arena, ctx.environ_map, target, opts);

    if (matches.len == 0) {
        return directQuery(ctx, target);
    }

    var found = false;
    var query_used = false;
    var seen_names: [8][]const u8 = undefined;
    var seen_count: usize = 0;
    for (matches, 0..) |m, i| {
        if (i > 0) try ctx.stdout_writer.writeByte('\n');

        const symlink = symlinkTarget(ctx.gpa, ctx.io, m.path);
        defer if (symlink) |s| ctx.gpa.free(s);
        try output.printName(ctx.stdout_writer, ctx.style, m.path, symlink);

        for (always_providers) |p| {
            const pctx: provider.Context = .{
                .gpa = ctx.gpa,
                .path = m.path,
                .io = ctx.io,
                .environ_map = ctx.environ_map,
            };
            const facts = p.run(pctx) catch |err| {
                try output.printError(ctx.stderr_writer, ctx.style, @errorName(err));
                continue;
            };
            defer freeFacts(ctx.gpa, facts);
            for (facts) |f| try output.printFact(ctx.stdout_writer, ctx.style, f);
        }

        // Run pacman once per distinct query name; several matches share one.
        const search_name = searchName(is_explicit_path, target, m);
        if (std.mem.eql(u8, search_name, target)) query_used = true;
        if (!hasSeenName(seen_names[0..seen_count], search_name)) {
            if (seen_count < seen_names.len) {
                seen_names[seen_count] = search_name;
                seen_count += 1;
                _ = try runPacmanAndPrint(ctx, search_name, false, false);
            }
        }
        found = true;
    }

    // A bare query no section used as its pacman name gets its own section,
    // because the resolved name (e.g. libz.so) is a different query than "z".
    if (!is_explicit_path and !query_used) {
        found = try runPacmanAndPrint(ctx, target, true, true) or found;
    }

    return found;
}

/// exe and explicit paths query pacman by the query itself; libs query by the
/// version-stripped SONAME because pacman basename matching keys on the file:
/// /lib/libz.so -> "libz.so", not the resolved path.
fn searchName(is_explicit_path: bool, query: []const u8, m: discover.Match) []const u8 {
    if (is_explicit_path) return query;
    if (m.from_binary) return query;
    return libSoname(m.path);
}

/// Returns a sub-slice of `path`; callers must not free it.
fn libSoname(path: []const u8) []const u8 {
    var base = std.fs.path.basename(path);
    while (base.len > 0) {
        const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse break;
        const tail = base[dot + 1 ..];
        if (tail.len == 0) break;
        var all_digits = true;
        for (tail) |c| if (!std.ascii.isDigit(c)) {
            all_digits = false;
            break;
        };
        if (!all_digits) break;
        base = base[0..dot];
    }
    return base;
}

fn hasSeenName(seen: []const []const u8, name: []const u8) bool {
    for (seen) |s| if (std.mem.eql(u8, s, name)) return true;
    return false;
}

fn directQuery(ctx: *RunContext, target: []const u8) !bool {
    const printed = try runPacmanAndPrint(ctx, target, true, false);
    if (!printed) {
        try ctx.stderr_writer.writeAll("error: not found: ");
        try ctx.stderr_writer.writeAll(target);
        try ctx.stderr_writer.writeAll("\n");
        ctx.stderr_writer.flush() catch {};
        return false;
    }
    return true;
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

fn symlinkTarget(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    // readLink returns error.NotLink for regular files, so a single call
    // covers both "is a symlink" and "what does it point to".
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().readLink(io, path, &buf) catch return null;
    return gpa.dupe(u8, buf[0..n]) catch null;
}

fn printUsage(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: wh [OPTIONS] NAME...
        \\
        \\Query package files, or show metadata for a specific file path.
        \\
        \\Options:
        \\  -a, --all       Show all resolved library matches
        \\  -l, --libs      Resolve NAME to a library path and show its metadata
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
