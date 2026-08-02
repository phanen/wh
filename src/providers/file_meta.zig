//! File metadata provider: type, size, permissions, owner, mtime.

const std = @import("std");
const builtin = @import("builtin");
const provider = @import("../provider.zig");
const Context = provider.Context;
const Fact = provider.Fact;

pub fn run(ctx: Context) anyerror![]Fact {
    var facts: std.ArrayList(Fact) = .empty;
    errdefer {
        for (facts.items) |f| {
            ctx.gpa.free(f.key);
            ctx.gpa.free(f.value);
        }
        facts.deinit(ctx.gpa);
    }

    const linux = std.os.linux;

    if (builtin.os.tag != .linux) {
        @compileError("file_meta currently supports Linux only");
    }

    const path_z = std.posix.toPosixPath(ctx.path) catch return try facts.toOwnedSlice(ctx.gpa);

    // Detect symlink without following (so the link mode bits aren't reported).
    var link_stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const link_rc = linux.statx(
        linux.AT.FDCWD,
        &path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .MODE = true },
        &link_stx,
    );
    const is_symlink = if (link_rc == 0)
        (link_stx.mode & linux.S.IFMT) == linux.S.IFLNK
    else
        false;

    if (is_symlink) {
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = std.Io.Dir.cwd().readLink(ctx.io, ctx.path, &link_buf) catch
            return try facts.toOwnedSlice(ctx.gpa);
        const target = link_buf[0..n];
        try facts.append(ctx.gpa, .{
            .key = try ctx.gpa.dupe(u8, "Symlink"),
            .value = try std.fmt.allocPrint(ctx.gpa, "{s} -> {s}", .{ ctx.path, target }),
            .group = "file_meta",
        });
    }

    // Stat the real file (follows symlinks when flags = 0).
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        &path_z,
        0,
        .{
            .TYPE = true,
            .MODE = true,
            .UID = true,
            .GID = true,
            .SIZE = true,
            .MTIME = true,
        },
        &stx,
    );
    if (rc != 0) return try facts.toOwnedSlice(ctx.gpa);

    const type_mask: u16 = stx.mode & linux.S.IFMT;
    const type_char = fileTypeChar(type_mask);

    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, "Type"),
        .value = try fileTypeString(ctx.gpa, type_mask),
        .group = "file_meta",
    });

    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, "Size"),
        .value = try sizeString(ctx.gpa, stx.size),
        .group = "file_meta",
    });

    const perm_bits: u16 = stx.mode & 0o7777;
    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, "Perms"),
        .value = try permsString(ctx.gpa, type_char, perm_bits),
        .group = "file_meta",
    });

    const owner_str = try ownerString(ctx.gpa, stx.uid, stx.gid);
    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, "Owner"),
        .value = owner_str,
        .group = "file_meta",
    });

    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, "Modified"),
        .value = try mtimeString(ctx.gpa, stx.mtime.sec, stx.mtime.nsec),
        .group = "file_meta",
    });

    return try facts.toOwnedSlice(ctx.gpa);
}

fn fileTypeChar(type_mask: u16) u8 {
    const linux = std.os.linux;
    return if (type_mask == linux.S.IFREG)
        '-'
    else if (type_mask == linux.S.IFDIR)
        'd'
    else if (type_mask == linux.S.IFLNK)
        'l'
    else if (type_mask == linux.S.IFCHR)
        'c'
    else if (type_mask == linux.S.IFBLK)
        'b'
    else if (type_mask == linux.S.IFIFO)
        'p'
    else if (type_mask == linux.S.IFSOCK)
        's'
    else
        '?';
}

fn fileTypeString(allocator: std.mem.Allocator, type_mask: u16) ![]u8 {
    const linux = std.os.linux;
    const name: []const u8 = if (type_mask == linux.S.IFREG)
        "regular file"
    else if (type_mask == linux.S.IFDIR)
        "directory"
    else if (type_mask == linux.S.IFLNK)
        "symbolic link"
    else if (type_mask == linux.S.IFCHR)
        "character device"
    else if (type_mask == linux.S.IFBLK)
        "block device"
    else if (type_mask == linux.S.IFIFO)
        "named pipe"
    else if (type_mask == linux.S.IFSOCK)
        "unix domain socket"
    else
        "unknown";
    return allocator.dupe(u8, name);
}

fn sizeString(allocator: std.mem.Allocator, size: u64) ![]u8 {
    const k: u64 = 1024;
    const m: u64 = k * 1024;
    const g: u64 = m * 1024;
    const t: u64 = g * 1024;

    if (size >= t) {
        const whole = size / t;
        const rem1 = size - whole * t;
        const frac = rem1 * 10 / t;
        return std.fmt.allocPrint(allocator, "{d}.{d} TiB", .{ whole, frac });
    }
    if (size >= g) {
        const whole = size / g;
        const rem1 = size - whole * g;
        const frac = rem1 * 10 / g;
        return std.fmt.allocPrint(allocator, "{d}.{d} GiB", .{ whole, frac });
    }
    if (size >= m) {
        const whole = size / m;
        const rem1 = size - whole * m;
        const frac = rem1 * 10 / m;
        return std.fmt.allocPrint(allocator, "{d}.{d} MiB", .{ whole, frac });
    }
    if (size >= k) {
        const whole = size / k;
        const rem1 = size - whole * k;
        const frac = rem1 * 10 / k;
        return std.fmt.allocPrint(allocator, "{d}.{d} KiB", .{ whole, frac });
    }
    return std.fmt.allocPrint(allocator, "{d} B", .{size});
}

fn permsString(
    allocator: std.mem.Allocator,
    type_char: u8,
    perm_bits: u16,
) ![]u8 {
    var buf: [10]u8 = undefined;
    const linux = std.os.linux;
    const u: u16 = (perm_bits >> 6) & 0o7;
    const g: u16 = (perm_bits >> 3) & 0o7;
    const o: u16 = perm_bits & 0o7;

    buf[0] = type_char;
    buf[1] = permChar((u & 0o4) != 0, 'r');
    buf[2] = permChar((u & 0o2) != 0, 'w');
    buf[3] = if ((perm_bits & linux.S.ISUID) != 0)
        permChar((u & 0o1) != 0, 's')
    else
        permChar((u & 0o1) != 0, 'x');
    buf[4] = permChar((g & 0o4) != 0, 'r');
    buf[5] = permChar((g & 0o2) != 0, 'w');
    buf[6] = if ((perm_bits & linux.S.ISGID) != 0)
        permChar((g & 0o1) != 0, 's')
    else
        permChar((g & 0o1) != 0, 'x');
    buf[7] = permChar((o & 0o4) != 0, 'r');
    buf[8] = permChar((o & 0o2) != 0, 'w');
    buf[9] = if ((perm_bits & linux.S.ISVTX) != 0)
        permChar((o & 0o1) != 0, 't')
    else
        permChar((o & 0o1) != 0, 'x');
    return allocator.dupe(u8, &buf);
}

fn permChar(cond: bool, c: u8) u8 {
    return if (cond) c else '-';
}

fn ownerString(allocator: std.mem.Allocator, uid: u32, gid: u32) ![]u8 {
    var user_buf: [16]u8 = undefined;
    var group_buf: [16]u8 = undefined;
    const user = lookupUser(uid, &user_buf);
    const group = lookupGroup(gid, &group_buf);
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ user, group });
}

fn lookupUser(uid: u32, buf: *[16]u8) []u8 {
    if (builtin.link_libc) {
        const pw = std.c.getpwuid(uid);
        if (pw) |p| if (p.name) |n| {
            const name = std.mem.span(n);
            if (name.len <= buf.len) {
                @memcpy(buf, name);
                return buf[0..name.len];
            }
        };
    }
    const len = std.fmt.printInt(buf, uid, 10, .lower, .{});
    return buf[0..len];
}

fn lookupGroup(gid: u32, buf: *[16]u8) []u8 {
    if (builtin.link_libc) {
        const gr = std.c.getgrgid(gid);
        if (gr) |g| if (g.name) |n| {
            const name = std.mem.span(n);
            if (name.len <= buf.len) {
                @memcpy(buf, name);
                return buf[0..name.len];
            }
        };
    }
    const len = std.fmt.printInt(buf, gid, 10, .lower, .{});
    return buf[0..len];
}

fn mtimeString(allocator: std.mem.Allocator, sec: i64, nsec: u32) ![]u8 {
    const secs: u64 = if (sec < 0) 0 else @intCast(sec);
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{s}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}",
        .{
            year_day.year,
            months[@intFromEnum(month_day.month) - 1],
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
            nsec,
        },
    );
}

test "file_meta: size formatting" {
    const allocator = std.testing.allocator;
    {
        const s = try sizeString(allocator, 512);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("512 B", s);
    }
    {
        const s = try sizeString(allocator, 1024);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("1.0 KiB", s);
    }
    {
        const s = try sizeString(allocator, 1024 + 512);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("1.5 KiB", s);
    }
}

test "file_meta: large size formatting" {
    const allocator = std.testing.allocator;
    const t: u64 = 1024 * 1024 * 1024 * 1024;
    {
        const s = try sizeString(allocator, t * 2);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("2.0 TiB", s);
    }
    {
        const s = try sizeString(allocator, 1024 * 1024 * 1024);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("1.0 GiB", s);
    }
}

test "file_meta: type char" {
    try std.testing.expectEqual('-', fileTypeChar(std.os.linux.S.IFREG));
    try std.testing.expectEqual('d', fileTypeChar(std.os.linux.S.IFDIR));
    try std.testing.expectEqual('l', fileTypeChar(std.os.linux.S.IFLNK));
}

test "file_meta: perms string" {
    const allocator = std.testing.allocator;
    {
        const s = try permsString(allocator, '-', 0o755);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("-rwxr-xr-x", s);
    }
    {
        const s = try permsString(allocator, '-', 0o644);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("-rw-r--r--", s);
    }
    {
        const s = try permsString(allocator, 'd', 0o755);
        defer allocator.free(s);
        try std.testing.expectEqualStrings("drwxr-xr-x", s);
    }
}
