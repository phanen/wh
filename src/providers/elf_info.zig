//! ELF info provider: format details (class, endian, type, machine, interpreter).

const std = @import("std");
const provider = @import("../provider.zig");
const elf_parse = @import("../elf_parse.zig");
const Context = provider.Context;
const Fact = provider.Fact;
const key = provider.fact_key;

pub fn run(ctx: Context) ![]Fact {
    var facts: std.ArrayList(Fact) = .empty;
    errdefer provider.deinitFacts(ctx.gpa, &facts);

    var parsed = elf_parse.parseFile(ctx.gpa, ctx.io, ctx.path) catch
        return try facts.toOwnedSlice(ctx.gpa);
    defer parsed.deinit(ctx.gpa);

    var desc: [128]u8 = undefined;
    const class_str: []const u8 = if (parsed.header.is_64) "64-bit" else "32-bit";
    const endian_str: []const u8 = switch (parsed.header.endian) {
        .little => "LSB",
        .big => "MSB",
    };
    const type_str: []const u8 = switch (parsed.header.type) {
        .EXEC => "executable",
        .DYN => "shared object",
        .REL => "relocatable",
        .CORE => "core file",
        else => "unknown",
    };
    const machine_str = machineName(parsed.header.machine);

    const line = std.fmt.bufPrint(
        &desc,
        "ELF {s} {s} {s}, {s}",
        .{ class_str, endian_str, type_str, machine_str },
    ) catch "ELF binary";
    try facts.append(ctx.gpa, .{
        .key = try ctx.gpa.dupe(u8, key.elf),
        .value = try ctx.gpa.dupe(u8, line),
    });

    if (parsed.interp) |interp| {
        try facts.append(ctx.gpa, .{
            .key = try ctx.gpa.dupe(u8, key.interpreter),
            .value = try ctx.gpa.dupe(u8, interp),
        });
    }

    return try facts.toOwnedSlice(ctx.gpa);
}

fn machineName(machine: std.elf.EM) []const u8 {
    return switch (machine) {
        .NONE => "no machine",
        .@"386" => "i386",
        .X86_64 => "x86-64",
        .AARCH64 => "AArch64",
        .ARM => "ARM",
        .MIPS => "MIPS",
        .PPC => "PowerPC",
        .PPC64 => "PowerPC64",
        .RISCV => "RISC-V",
        .S390 => "s390",
        .SPARC => "SPARC",
        .SPARC32PLUS, .SPARCV9 => "SPARC V9",
        .IA_64 => "IA-64",
        .OLD_ALPHA => "Alpha",
        .PARISC => "HPPA",
        .S370 => "S370",
        .MIPS_X => "MIPS-X",
        .@"68K" => "m68k",
        .@"88K" => "m88k",
        .VAX => "VAX",
        .AVR => "AVR",
        .MSP430 => "MSP430",
        .SH => "SuperH",
        .ARC => "ARC",
        .LANAI => "Lanai",
        else => @tagName(machine),
    };
}
