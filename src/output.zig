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

pub fn printPathOnly(
    writer: *std.Io.Writer,
    style: Style,
    path: []const u8,
) !void {
    try printPath(writer, style, path);
}

pub fn printFact(
    writer: *std.Io.Writer,
    style: Style,
    fact: Fact,
) !void {
    try outputInnerPrintFact(writer, style, fact);
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

fn printPath(
    writer: *std.Io.Writer,
    style: Style,
    path: []const u8,
) !void {
    if (style.color) try writer.writeAll("\x1b[1;36m");
    try writer.writeAll(path);
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll("\n");
}

fn outputInnerPrintFact(
    writer: *std.Io.Writer,
    style: Style,
    fact: Fact,
) !void {
    if (std.mem.indexOfScalar(u8, fact.value, '\n') != null) {
        try printMultilineFact(writer, style, fact);
        return;
    }

    try writer.writeAll("  ");
    if (style.color) try writer.writeAll("\x1b[2m");
    try writer.print("{s}:", .{fact.key});
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll(" ");

    if (std.mem.eql(u8, fact.key, "Perms")) {
        try printPerms(writer, style, fact.value);
    } else {
        try writer.writeAll(fact.value);
    }
    try writer.writeAll("\n");
}

fn printMultilineFact(
    writer: *std.Io.Writer,
    style: Style,
    fact: Fact,
) !void {
    try writer.writeAll("  ");
    if (style.color) try writer.writeAll("\x1b[2m");
    try writer.print("{s}:", .{fact.key});
    if (style.color) try writer.writeAll("\x1b[0m");
    try writer.writeAll("\n");

    var it = std.mem.splitScalar(u8, fact.value, '\n');
    while (it.next()) |line| {
        try writer.writeAll("    ");
        if (std.mem.eql(u8, fact.key, "Deps")) {
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
