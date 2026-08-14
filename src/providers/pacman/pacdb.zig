//! Pacman local DB provider: shows which package owns a file (-Qo).

const std = @import("std");
const provider = @import("../../provider.zig");
const util = @import("../../util.zig");
const Context = provider.Context;

const pacman_local_dir = "/var/lib/pacman/local";
/// Safety cap for a single package's `files` list. Real lists top out around
/// 9 MB (linux-zen-docs); a far larger value signals a corrupt file.
const max_files_size: usize = 256 * 1024 * 1024;

/// The locally-installed package that owns the target file, if any.
/// At most one package can own a file, so this is an optional not a list.
pub const LocalPkg = struct {
    name: []const u8,
    version: []const u8,
    filepath: []const u8,

    pub fn free(self: LocalPkg, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.filepath);
    }
};

pub fn run(ctx: Context) !?LocalPkg {
    const target = ctx.path;

    var local_dir = std.Io.Dir.openDirAbsolute(ctx.io, pacman_local_dir, .{
        .iterate = true,
    }) catch return null;
    defer local_dir.close(ctx.io);

    var iter = local_dir.iterate();
    while (try iter.next(ctx.io)) |entry| {
        if (entry.kind != .directory) continue;

        var path_buf: [std.posix.PATH_MAX]u8 = undefined;
        const files_path = std.fmt.bufPrint(&path_buf, "{s}/files", .{entry.name}) catch continue;
        var files = local_dir.openFile(ctx.io, files_path, .{}) catch continue;
        defer files.close(ctx.io);

        var read_buf: [16 * 1024]u8 = undefined;
        var file_reader = files.reader(ctx.io, &read_buf);
        const opt_match = try findInFiles(ctx.gpa, &file_reader.interface, target);
        if (opt_match) |match| {
            defer match.free(ctx.gpa);

            const split = splitPkgDirName(entry.name);
            return LocalPkg{
                .name = try ctx.gpa.dupe(u8, split.name),
                .version = try ctx.gpa.dupe(u8, split.version),
                .filepath = try ctx.gpa.dupe(u8, match.path),
            };
        }
    }

    return null;
}

/// Drains the whole `files` list through the buffered reader into one
/// allocation and searches only the %FILES% section.
fn findInFiles(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    target: []const u8,
) !?Match {
    const data = reader.allocRemaining(allocator, .limited(max_files_size)) catch return null;
    defer allocator.free(data);

    const matched = util.matchFind(target, data) orelse return null;
    return Match{ .path = try allocator.dupe(u8, matched) };
}

const Match = struct {
    path: []const u8,

    fn free(self: Match, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

pub const PkgDirSplit = struct { name: []const u8, version: []const u8 };

pub fn splitPkgDirName(dir_name: []const u8) PkgDirSplit {
    var dash_count: usize = 0;
    var version_start: usize = dir_name.len;
    var i: usize = dir_name.len;
    while (i > 0) {
        i -= 1;
        if (dir_name[i] == '-') {
            dash_count += 1;
            if (dash_count == 2) {
                version_start = i + 1;
                return .{ .name = dir_name[0..i], .version = dir_name[version_start..] };
            }
        }
    }
    return .{ .name = dir_name, .version = "" };
}

test "pacdb: findInFiles finds exact match in %FILES% section" {
    const data =
        \\%NAME%
        \\coreutils
        \\
        \\%FILES%
        \\usr/
        \\usr/bin/
        \\usr/bin/ls
        \\usr/lib/somelib.so
        \\
        \\%BACKUP%
        \\etc/foo.conf\tabc123
        \\
    ;

    var reader1: std.Io.Reader = .fixed(data);
    const match1 = (try findInFiles(std.testing.allocator, &reader1, "usr/bin/ls")).?;
    defer match1.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/bin/ls", match1.path);

    var reader2: std.Io.Reader = .fixed(data);
    const match2 = (try findInFiles(std.testing.allocator, &reader2, "usr/lib/somelib.so")).?;
    defer match2.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/lib/somelib.so", match2.path);

    var reader3: std.Io.Reader = .fixed(data);
    try std.testing.expect(try findInFiles(std.testing.allocator, &reader3, "etc/foo.conf") == null);

    var reader4: std.Io.Reader = .fixed(data);
    try std.testing.expect(try findInFiles(std.testing.allocator, &reader4, "usr/bin/cat") == null);
}

test "pacdb: findInFiles supports bare basename match" {
    const data =
        \\%FILES%
        \\usr/bin/ls
        \\usr/share/doc/ls/README
        \\
    ;

    var reader: std.Io.Reader = .fixed(data);
    const match = (try findInFiles(std.testing.allocator, &reader, "ls")).?;
    defer match.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/bin/ls", match.path);
}

test "pacdb: findInFiles handles trailing whitespace" {
    const data = "%FILES%\nusr/bin/ls  \r\n%BACKUP%\n";

    var reader: std.Io.Reader = .fixed(data);
    const match = try findInFiles(std.testing.allocator, &reader, "usr/bin/ls");
    try std.testing.expect(match != null);
    if (match) |m| m.free(std.testing.allocator);
}

test "pacdb: findInFiles stops at next %SECTION%" {
    const data =
        \\%FILES%
        \\usr/bin/ls
        \\%BACKUP%
        \\etc/ls.conf\thash
        \\
    ;

    var reader: std.Io.Reader = .fixed(data);
    const match = try findInFiles(std.testing.allocator, &reader, "etc/ls.conf");
    try std.testing.expect(match == null);
}

test "pacdb: splitPkgDirName extracts name and version" {
    const s = splitPkgDirName("coreutils-9.11-2");
    try std.testing.expectEqualStrings("coreutils", s.name);
    try std.testing.expectEqualStrings("9.11-2", s.version);
}
