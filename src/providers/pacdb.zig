//! Pacman local DB provider: shows which package owns a file (-Qo).

const std = @import("std");
const util = @import("../util.zig");
const provider = @import("../provider.zig");
const Context = provider.Context;
const Fact = provider.Fact;

const pacman_local_dir = "/var/lib/pacman/local";

pub fn run(ctx: Context) anyerror![]Fact {
    var facts: std.ArrayList(Fact) = .empty;
    errdefer {
        for (facts.items) |f| {
            ctx.gpa.free(f.key);
            ctx.gpa.free(f.value);
        }
        facts.deinit(ctx.gpa);
    }

    const target = ctx.path;
    const bare = std.mem.indexOfScalar(u8, target, '/') == null;

    var local_dir = std.Io.Dir.openDirAbsolute(ctx.io, pacman_local_dir, .{
        .iterate = true,
    }) catch return try facts.toOwnedSlice(ctx.gpa);
    defer local_dir.close(ctx.io);
    const local_fd = local_dir.handle;

    var iter = local_dir.iterate();
    while (try iter.next(ctx.io)) |entry| {
        if (entry.kind != .directory) continue;

        var path_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
        const files_path = std.fmt.bufPrint(&path_buf, "{s}/files", .{entry.name}) catch continue;
        const files_fd = std.posix.openat(local_fd, files_path, .{}, 0) catch continue;
        defer _ = std.os.linux.close(files_fd);

        const opt_match = try findInFiles(ctx.gpa, files_fd, target, bare);
        if (opt_match) |match| {
            defer match.free(ctx.gpa);

            const split = splitPkgDirName(entry.name);

            try facts.append(ctx.gpa, .{
                .key = try ctx.gpa.dupe(u8, "Package"),
                .value = try ctx.gpa.dupe(u8, split.name),
            });
            try facts.append(ctx.gpa, .{
                .key = try ctx.gpa.dupe(u8, "Version"),
                .value = try ctx.gpa.dupe(u8, split.version),
            });
            try facts.append(ctx.gpa, .{
                .key = try ctx.gpa.dupe(u8, "FilePath"),
                .value = try ctx.gpa.dupe(u8, match.path),
            });
            break;
        }
    }

    return try facts.toOwnedSlice(ctx.gpa);
}

fn findInFiles(allocator: std.mem.Allocator, fd: std.posix.fd_t, target: []const u8, bare: bool) !?Match {
    var stack_buf: [65536]u8 = undefined;
    var total: usize = 0;

    while (total < stack_buf.len) {
        const n = std.posix.read(fd, stack_buf[total..]) catch return null;
        if (n == 0) break;
        total += n;
    }

    if (total < stack_buf.len) {
        return scanLines(allocator, stack_buf[0..total], target, bare);
    }

    const heap_buf = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(heap_buf);
    @memcpy(heap_buf[0..total], stack_buf[0..total]);

    while (total < heap_buf.len) {
        const n = std.posix.read(fd, heap_buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    return scanLines(allocator, heap_buf[0..total], target, bare);
}

fn scanLines(allocator: std.mem.Allocator, data: []const u8, target: []const u8, bare: bool) !?Match {
    var iter = std.mem.splitScalar(u8, data, '\n');
    while (iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r");
        if (std.mem.eql(u8, target, trimmed)) {
            return Match{ .path = try allocator.dupe(u8, trimmed), .owned = true };
        }
        if (bare) {
            const filename = std.fs.path.basename(trimmed);
            if (std.mem.eql(u8, target, filename)) {
                return Match{ .path = try allocator.dupe(u8, trimmed), .owned = true };
            }
        }
    }
    return null;
}

const Match = struct {
    path: []const u8,
    owned: bool,

    fn free(self: Match, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.path);
    }
};

const PkgDirSplit = struct { name: []const u8, version: []const u8 };

fn splitPkgDirName(dir_name: []const u8) PkgDirSplit {
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

fn makeTestFd(data: []const u8) std.posix.fd_t {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.pipe2(&fds, .{ .CLOEXEC = true });
    if (std.os.linux.errno(rc) != .SUCCESS) unreachable;
    const written = std.os.linux.write(fds[1], data.ptr, data.len);
    std.debug.assert(written == data.len);
    _ = std.os.linux.close(fds[1]);
    return fds[0];
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

    const fd1 = makeTestFd(data);
    defer _ = std.os.linux.close(fd1);
    const match1 = (try findInFiles(std.testing.allocator, fd1, "usr/bin/ls", false)).?;
    defer match1.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/bin/ls", match1.path);

    const fd2 = makeTestFd(data);
    defer _ = std.os.linux.close(fd2);
    const match2 = (try findInFiles(std.testing.allocator, fd2, "usr/lib/somelib.so", false)).?;
    defer match2.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/lib/somelib.so", match2.path);

    const fd3 = makeTestFd(data);
    defer _ = std.os.linux.close(fd3);
    try std.testing.expect(try findInFiles(std.testing.allocator, fd3, "etc/foo.conf", false) == null);

    const fd4 = makeTestFd(data);
    defer _ = std.os.linux.close(fd4);
    try std.testing.expect(try findInFiles(std.testing.allocator, fd4, "usr/bin/cat", false) == null);
}

test "pacdb: findInFiles supports bare basename match" {
    const data =
        \\%FILES%
        \\usr/bin/ls
        \\usr/share/doc/ls/README
        \\
    ;

    const fd = makeTestFd(data);
    defer _ = std.os.linux.close(fd);

    const match = (try findInFiles(std.testing.allocator, fd, "ls", true)).?;
    defer match.free(std.testing.allocator);
    try std.testing.expectEqualStrings("usr/bin/ls", match.path);
}

test "pacdb: findInFiles handles trailing whitespace" {
    const data = "%FILES%\nusr/bin/ls  \r\n%BACKUP%\n";

    const fd = makeTestFd(data);
    defer _ = std.os.linux.close(fd);

    const match = try findInFiles(std.testing.allocator, fd, "usr/bin/ls", false);
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

    const fd = makeTestFd(data);
    defer _ = std.os.linux.close(fd);

    const match = try findInFiles(std.testing.allocator, fd, "etc/ls.conf", false);
    try std.testing.expect(match == null);
}

test "pacdb: splitPkgDirName extracts name and version" {
    const s = splitPkgDirName("coreutils-9.11-2");
    try std.testing.expectEqualStrings("coreutils", s.name);
    try std.testing.expectEqualStrings("9.11-2", s.version);
}
