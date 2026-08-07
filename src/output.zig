//! Colored terminal output for wh.

const std = @import("std");
const provider = @import("provider.zig");
const Fact = provider.Fact;

pub const Style = struct {
    color: bool,
};

pub fn detectStyle(io: std.Io, file: std.Io.File, environ_map: *const std.process.Environ.Map) Style {
    const is_tty = file.isTty(io) catch false;
    const no_color_env = environ_map.contains("NO_COLOR");
    return .{ .color = is_tty and !no_color_env };
}

pub fn printFact(
    writer: *std.Io.Writer,
    style: Style,
    fact: Fact,
) !void {
    if (std.mem.eql(u8, fact.key, "Pkg")) {
        try printPkg(writer, style, fact.value);
        return;
    }
    if (std.mem.eql(u8, fact.key, "Stat")) {
        try printStat(writer, style, fact.value);
        return;
    }
    if (std.mem.indexOfScalar(u8, fact.value, '\n') != null) {
        try printMultilineFact(writer, style, fact);
        return;
    }

    try writer.writeAll("  ");
    if (style.color) try writer.writeAll("\x1b[2m");
    try writer.print("{s}:", .{fact.key});
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");

    try writer.writeAll(fact.value);
    try writer.writeAll("\n");
}

pub fn printError(
    writer: *std.Io.Writer,
    style: Style,
    message: []const u8,
) !void {
    if (style.color) try writer.writeAll("\x1b[1;31m");
    try writer.writeAll("error: ");
    try writer.writeAll(message);
    try writer.writeAll("\n");
    if (style.color) try writer.writeAll("\x1b[0m");
}

pub fn printName(
    writer: *std.Io.Writer,
    style: Style,
    path: []const u8,
    target: ?[]const u8,
) !void {
    try writer.writeAll("  ");
    if (style.color) try writer.writeAll("\x1b[2m");
    try writer.writeAll("Name:");
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");
    if (style.color) try writer.writeAll("\x1b[1;36m");
    try writer.writeAll(path);
    if (style.color) try writer.writeAll("\x1b[0m");
    if (target) |t| {
        if (style.color) try writer.writeAll("\x1b[2m");
        try writer.writeAll(" -> ");
        if (style.color) try writer.writeAll("\x1b[0m");
        if (style.color) try writer.writeAll("\x1b[1;36m");
        try writer.writeAll(t);
        if (style.color) try writer.writeAll("\x1b[0m");
    }
    try writer.writeAll("\n");
}

fn printMultilineFact(
    writer: *std.Io.Writer,
    style: Style,
    fact: Fact,
) !void {
    const is_deps = std.mem.eql(u8, fact.key, "Deps");

    if (!is_deps) {
        try writer.writeAll("  ");
        if (style.color) try writer.writeAll("\x1b[2m");
        try writer.print("{s}:", .{fact.key});
        if (style.color) try writer.writeAll("\x1b[0m");
        try writer.writeAll("\n");
    }

    var it = std.mem.splitScalar(u8, fact.value, '\n');
    while (it.next()) |line| {
        try writer.writeAll("  ");
        if (is_deps) {
            try printDepLine(writer, style, line);
        } else {
            try writer.writeAll(line);
        }
        try writer.writeAll("\n");
    }
}

fn printDepLine(
    writer: *std.Io.Writer,
    style: Style,
    line: []const u8,
) !void {
    const sep = " => ";
    const pos = std.mem.indexOf(u8, line, sep) orelse {
        try writer.writeAll(line);
        return;
    };
    const soname = line[0..pos];
    const path = line[pos + sep.len ..];

    if (style.color) try writer.writeAll("\x1b[1;37m");
    try writer.writeAll(soname);
    if (style.color) try writer.writeAll("\x1b[0m");

    if (style.color) try writer.writeAll("\x1b[2m");
    try writer.writeAll(sep);
    if (style.color) try writer.writeAll("\x1b[0m");

    try printDepPath(writer, style, path);
}

fn printDepPath(
    writer: *std.Io.Writer,
    style: Style,
    path: []const u8,
) !void {
    if (std.mem.eql(u8, path, "not found")) {
        if (style.color) try writer.writeAll("\x1b[31m");
        try writer.writeAll(path);
        if (style.color) try writer.writeAll("\x1b[0m");
    } else if (path.len > 0 and path[0] == '(') {
        if (style.color) try writer.writeAll("\x1b[33m");
        try writer.writeAll(path);
        if (style.color) try writer.writeAll("\x1b[0m");
    } else {
        if (style.color) try writer.writeAll("\x1b[32m");
        try writer.writeAll(path);
        if (style.color) try writer.writeAll("\x1b[0m");
    }
}

fn printStat(
    writer: *std.Io.Writer,
    style: Style,
    value: []const u8,
) !void {
    try writer.writeAll("  ");

    // Format: "<perms 10 chars> <size> <owner> <date>"
    // size may be "<num>" or "<num> <unit>" (e.g. "162.7 KiB").
    // owner is always "user:group" (no spaces).
    if (value.len < 11 or value[10] != ' ') {
        try writer.writeAll(value);
        try writer.writeAll("\n");
        return;
    }
    const perms = value[0..10];
    try printPerms(writer, style, perms);
    try writer.writeAll(" ");

    var rest = value[11..];
    var lead: usize = 0;
    while (lead < rest.len and rest[lead] == ' ') : (lead += 1) {}
    rest = rest[lead..];

    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };

    var size_take: usize = 0;
    var iter = std.mem.splitScalar(u8, rest, ' ');
    if (iter.next()) |first| {
        size_take += first.len + 1;
        if (iter.next()) |maybe_unit| {
            var is_unit = false;
            for (units) |u| if (std.mem.eql(u8, maybe_unit, u)) {
                is_unit = true;
                break;
            };
            if (is_unit) size_take += maybe_unit.len + 1;
        }
    }

    const size = rest[0..size_take - 1];
    if (style.color) try writer.writeAll("\x1b[1;37m");
    try writer.writeAll(size);
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");

    var owner_iter = std.mem.splitScalar(u8, rest[size_take..], ' ');
    const owner = owner_iter.next() orelse {
        try writer.writeAll("\n");
        return;
    };
    if (style.color) try writer.writeAll("\x1b[33m");
    try writer.writeAll(owner);
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");

    const date = owner_iter.rest();
    if (style.color) try writer.writeAll("\x1b[36m");
    try writer.writeAll(date);
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll("\n");
}

fn printPerms(
    writer: *std.Io.Writer,
    style: Style,
    perm: []const u8,
) !void {
    if (!style.color or perm.len != 10) {
        try writer.writeAll(perm);
        return;
    }

    try writer.writeAll(&.{perm[0]});

    const r_indices = [_]usize{ 1, 4, 7 };
    for (r_indices) |i| try writePermChar(writer, perm[i], 'r', "\x1b[32m");

    const w_indices = [_]usize{ 2, 5, 8 };
    for (w_indices) |i| try writePermChar(writer, perm[i], 'w', "\x1b[33m");

    const x_indices = [_]usize{ 3, 6 };
    for (x_indices) |i| try writeExecChar(writer, perm[i], &.{ 'x', 's' });

    try writeExecChar(writer, perm[9], &.{ 'x', 't' });
}

fn writePermChar(
    writer: *std.Io.Writer,
    ch: u8,
    target: u8,
    on_color: []const u8,
) !void {
    if (ch == target) {
        try writer.writeAll(on_color);
        try writer.writeAll(&.{ch});
        try writer.writeAll("\x1b[0m");
    } else {
        try writer.writeAll("\x1b[2m");
        try writer.writeAll(&.{ch});
        try writer.writeAll("\x1b[0m");
    }
}

fn writeExecChar(
    writer: *std.Io.Writer,
    ch: u8,
    on_chars: []const u8,
) !void {
    const matched = for (on_chars) |c| {
        if (ch == c) break true;
    } else false;

    if (matched) {
        try writer.writeAll("\x1b[31m");
        try writer.writeAll(&.{ch});
        try writer.writeAll("\x1b[0m");
    } else {
        try writer.writeAll("\x1b[2m");
        try writer.writeAll(&.{ch});
        try writer.writeAll("\x1b[0m");
    }
}

fn printPkg(
    writer: *std.Io.Writer,
    style: Style,
    value: []const u8,
) !void {
    try writer.writeAll("  ");
    const slash = std.mem.indexOfScalar(u8, value, '/') orelse {
        try writer.writeAll(value);
        try writer.writeAll("\n");
        return;
    };
    const repo = value[0..slash];
    const rest = value[slash + 1 ..];

    if (style.color) try writer.writeAll("\x1b[1;35m");
    try writer.writeAll(repo);
    try writer.writeAll("/");
    if (style.color) try writer.writeAll("\x1b[0m");

    // Pull off trailing filepath token: anything after the last space, unless
    // that last token itself is a bracketed marker like [installed].
    var pkg_part: []const u8 = rest;
    var filepath: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, rest, ' ')) |ls_idx| {
        const last_token = rest[ls_idx + 1 ..];
        if (last_token.len > 0 and last_token[0] != '[') {
            pkg_part = rest[0..ls_idx];
            filepath = last_token;
        }
    }

    const space = std.mem.indexOfScalar(u8, pkg_part, ' ') orelse {
        try writer.writeAll(pkg_part);
        if (filepath) |fp| {
            try writer.writeAll(" ");
            if (style.color) try writer.writeAll("\x1b[37m");
            try writer.writeAll(fp);
            if (style.color) try writer.writeAll("\x1b[0m");
        }
        try writer.writeAll("\n");
        return;
    };
    const name = pkg_part[0..space];
    const after_name = pkg_part[space + 1 ..];

    const installed_marker = " [installed]";
    const has_installed = std.mem.endsWith(u8, after_name, installed_marker);
    const version = if (has_installed)
        after_name[0 .. after_name.len - installed_marker.len]
    else
        after_name;

    if (style.color) try writer.writeAll("\x1b[1m");
    try writer.writeAll(name);
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");
    if (style.color) try writer.writeAll("\x1b[1;32m");
    try writer.writeAll(version);
    if (style.color) try writer.writeAll("\x1b[0m");
    if (has_installed) {
        try writer.writeAll(" ");
        if (style.color) try writer.writeAll("\x1b[1;36m");
        try writer.writeAll("[installed]");
        if (style.color) try writer.writeAll("\x1b[0m");
    }
    if (filepath) |fp| {
        try writer.writeAll(" ");
        if (style.color) try writer.writeAll("\x1b[37m");
        try writer.writeAll(fp);
        if (style.color) try writer.writeAll("\x1b[0m");
    }
    try writer.writeAll("\n");
}
