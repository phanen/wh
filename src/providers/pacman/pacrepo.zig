//! Pacman sync DB provider (-F).

const std = @import("std");
const util = @import("../../util.zig");
const provider = @import("../../provider.zig");
const Context = provider.Context;
const Fact = provider.Fact;

const sync_dir = "/var/lib/pacman/sync";
const max_read_size: usize = 256 * 1024 * 1024;
const max_tar_entries: usize = 10_000_000;

pub const PkgMatch = struct {
    name: []const u8,
    version: []const u8,
    repo: []const u8,
    filepath: []const u8,

    pub fn free(self: PkgMatch, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.repo);
        allocator.free(self.filepath);
    }
};

pub fn run(ctx: Context) ![]PkgMatch {
    var results: std.ArrayList(PkgMatch) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        for (results.items) |m| m.free(ctx.gpa);
        results.deinit(ctx.gpa);
        var it = seen.iterator();
        while (it.next()) |e| ctx.gpa.free(e.key_ptr.*);
        seen.deinit(ctx.gpa);
    }

    const target = ctx.path;

    var dir = std.Io.Dir.openDirAbsolute(ctx.io, sync_dir, .{ .iterate = true }) catch
        return &.{};
    defer dir.close(ctx.io);

    var iter = dir.iterate();
    while (try iter.next(ctx.io)) |entry| {
        if (entry.kind != .file) continue;
        const parsed = parseDbName(entry.name) orelse continue;

        const db_matches = searchOneDb(ctx, entry.name, target, parsed.repo) catch continue;
        defer {
            for (db_matches) |m| {
                ctx.gpa.free(m.name);
                ctx.gpa.free(m.version);
                ctx.gpa.free(m.repo);
                ctx.gpa.free(m.filepath);
            }
            ctx.gpa.free(db_matches);
        }

        for (db_matches) |m| {
            const key = try std.fmt.allocPrint(ctx.gpa, "{s}/{s}/{s}", .{
                m.repo,
                m.name,
                m.filepath,
            });
            defer ctx.gpa.free(key);
            const gop = try seen.getOrPut(ctx.gpa, key);
            if (!gop.found_existing) {
                gop.key_ptr.* = try ctx.gpa.dupe(u8, key);
                try results.append(ctx.gpa, .{
                    .name = try ctx.gpa.dupe(u8, m.name),
                    .version = try ctx.gpa.dupe(u8, m.version),
                    .repo = try ctx.gpa.dupe(u8, m.repo),
                    .filepath = try ctx.gpa.dupe(u8, m.filepath),
                });
            }
        }
    }

    return try results.toOwnedSlice(ctx.gpa);
}

const DbName = struct {
    repo: []const u8,
};

fn parseDbName(name: []const u8) ?DbName {
    if (std.mem.endsWith(u8, name, ".files")) return .{ .repo = name[0 .. name.len - 6] };
    if (std.mem.endsWith(u8, name, ".db")) return .{ .repo = name[0 .. name.len - 3] };
    return null;
}

const PkgInfo = struct {
    name: []const u8,
    version: []const u8,
};

fn searchOneDb(
    ctx: Context,
    db_filename: []const u8,
    target: []const u8,
    repo: []const u8,
) ![]PkgMatch {
    const db_path = try std.fs.path.join(ctx.gpa, &.{ sync_dir, db_filename });
    defer ctx.gpa.free(db_path);

    const compressed = std.Io.Dir.cwd().readFileAlloc(
        ctx.io,
        db_path,
        ctx.gpa,
        .limited(max_read_size),
    ) catch return &.{};
    defer ctx.gpa.free(compressed);

    var input_reader: std.Io.Reader = .fixed(compressed);
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input_reader, .gzip, &decomp_buf);

    return searchTar(&decompressor.reader, target, repo, ctx.gpa);
}

fn searchTar(
    reader: *std.Io.Reader,
    target: []const u8,
    repo: []const u8,
    allocator: std.mem.Allocator,
) ![]PkgMatch {
    var info_map: std.StringHashMapUnmanaged(PkgInfo) = .empty;
    defer {
        var it = info_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.name);
            allocator.free(entry.value_ptr.version);
        }
        info_map.deinit(allocator);
    }

    const MatchEntry = struct { prefix: []const u8, filepath: []const u8 };
    var matched_list: std.ArrayList(MatchEntry) = .empty;
    defer {
        for (matched_list.items) |e| {
            allocator.free(e.prefix);
            allocator.free(e.filepath);
        }
        matched_list.deinit(allocator);
    }

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    var entry_count: usize = 0;
    while (try it.next()) |file| : (entry_count += 1) {
        if (entry_count >= max_tar_entries) return error.TooManyTarEntries;

        if (file.kind != .file) continue;
        if (file.size == 0) continue;

        var entry_data: std.Io.Writer.Allocating = .init(allocator);
        defer entry_data.deinit();
        try it.streamRemaining(file, &entry_data.writer);
        const data = entry_data.written();

        if (std.mem.endsWith(u8, file.name, "/desc")) {
            const prefix = file.name[0 .. file.name.len - 5];
            const name_val = util.parseDescField(data, "NAME", allocator) orelse
                try allocator.dupe(u8, prefix);
            errdefer allocator.free(name_val);

            const version_val = util.parseDescField(data, "VERSION", allocator) orelse
                try allocator.dupe(u8, "");
            errdefer allocator.free(version_val);

            const key = try allocator.dupe(u8, prefix);
            errdefer allocator.free(key);

            const gop = try info_map.getOrPut(allocator, key);
            if (gop.found_existing) {
                allocator.free(name_val);
                allocator.free(version_val);
                allocator.free(key);
            } else {
                gop.value_ptr.* = .{ .name = name_val, .version = version_val };
            }
        } else if (std.mem.endsWith(u8, file.name, "/files")) {
            if (util.matchFind(target, data)) |matched_path| {
                const prefix = try allocator.dupe(u8, file.name[0 .. file.name.len - 6]);
                errdefer allocator.free(prefix);
                try matched_list.append(allocator, .{
                    .prefix = prefix,
                    .filepath = try allocator.dupe(u8, matched_path),
                });
            }
        }
    }

    var results: std.ArrayList(PkgMatch) = .empty;
    for (matched_list.items) |entry| {
        if (info_map.get(entry.prefix)) |info| {
            try results.append(allocator, .{
                .name = try allocator.dupe(u8, info.name),
                .version = try allocator.dupe(u8, info.version),
                .repo = try allocator.dupe(u8, repo),
                .filepath = try allocator.dupe(u8, entry.filepath),
            });
        }
    }

    return try results.toOwnedSlice(allocator);
}

test "pacrepo: parseDbName splits suffixes" {
    {
        const p = parseDbName("core.db").?;
        try std.testing.expectEqualStrings("core", p.repo);
    }
    {
        const p = parseDbName("extra.files").?;
        try std.testing.expectEqualStrings("extra", p.repo);
    }
    try std.testing.expect(parseDbName("core.pacfiles") == null);
}

test "pacrepo: fileContains finds matches in %FILES% section" {
    const data =
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
    try std.testing.expect(util.fileContains("usr/bin/ls", data));
    try std.testing.expect(util.fileContains("usr/lib/somelib.so", data));
    try std.testing.expect(!util.fileContains("etc/foo.conf", data));
    try std.testing.expect(!util.fileContains("usr/bin/cat", data));
}

test "pacrepo: parseDescField extracts NAME and VERSION" {
    const allocator = std.testing.allocator;
    const data =
        \\%NAME%
        \\vim
        \\
        \\%VERSION%
        \\9.1.0932-1
        \\
    ;
    const name = util.parseDescField(data, "NAME", allocator).?;
    defer allocator.free(name);
    try std.testing.expectEqualStrings("vim", name);

    const version = util.parseDescField(data, "VERSION", allocator).?;
    defer allocator.free(version);
    try std.testing.expectEqualStrings("9.1.0932-1", version);

    try std.testing.expect(util.parseDescField(data, "SIZE", allocator) == null);
}

test "pacrepo: searchTar finds package from synthetic tar stream" {
    const allocator = std.testing.allocator;

    const desc_data =
        \\%NAME%
        \\demo
        \\
        \\%VERSION%
        \\1.2.3-4
        \\
    ;
    const files_data =
        \\%FILES%
        \\usr/
        \\usr/bin/
        \\usr/bin/demo
        \\
    ;

    var tar_buf: std.Io.Writer.Allocating = .init(allocator);
    defer tar_buf.deinit();

    var tar: std.tar.Writer = .{ .underlying_writer = &tar_buf.writer };
    try tar.writeFileBytes("demo-1.2.3-4/desc", desc_data, .{});
    try tar.writeFileBytes("demo-1.2.3-4/files", files_data, .{});
    // End-of-archive: two zero blocks.
    try tar_buf.writer.splatByteAll(0, 1024);

    var reader: std.Io.Reader = .fixed(tar_buf.written());
    const results = try searchTar(&reader, "usr/bin/demo", "testrepo", allocator);
    defer {
        for (results) |r| {
            allocator.free(r.name);
            allocator.free(r.version);
            allocator.free(r.repo);
            allocator.free(r.filepath);
        }
        allocator.free(results);
    }
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("demo", results[0].name);
    try std.testing.expectEqualStrings("1.2.3-4", results[0].version);
    try std.testing.expectEqualStrings("testrepo", results[0].repo);
    try std.testing.expectEqualStrings("usr/bin/demo", results[0].filepath);
}

test "pacrepo: searchTar returns empty when target not found" {
    const allocator = std.testing.allocator;
    var reader: std.Io.Reader = .fixed("");
    const result = try searchTar(&reader, "usr/bin/anything", "repo", allocator);
    defer allocator.free(result);
    try std.testing.expect(result.len == 0);
}
