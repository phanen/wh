const std = @import("std");

pub fn pathBaseMatches(path: []const u8, name: []const u8) bool {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return false;
    return std.mem.eql(u8, path[slash + 1 ..], name);
}

test "pathBaseMatches matches basename" {
    try std.testing.expect(pathBaseMatches("usr/bin/ls", "ls"));
    try std.testing.expect(pathBaseMatches("/etc/conf.d/foo", "foo"));
    try std.testing.expect(!pathBaseMatches("usr/bin/ls", "cat"));
    try std.testing.expect(!pathBaseMatches("bare", "bare"));
}
