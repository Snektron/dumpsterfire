const std = @import("std");
const Session = @import("Session.zig");
const Allocator = std.mem.Allocator;

const ar = @import("ar.zig");
const mib2 = @import("mib2.zig");

var log_verbose = false;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (log_verbose or @enumToInt(level) <= @enumToInt(std.log.Level.err)) {
        std.log.defaultLog(level, scope, format, args);
    }
}

const Options = struct {
    const Command = enum {
        help,
        status,
        wan_status,
        logout_current
    };

    const name_to_command = std.ComptimeStringMap(Command, .{
        .{"help", .help},
        .{"status", .status},
        .{"wan-status", .wan_status},
        .{"logout-current", .logout_current},
    });

    const default_username = "admin";

    args: [][:0]u8,

    command: Command,
    verbose: bool,
    force: bool,

    modem_address: []const u8,
    username: []const u8,
    password: []const u8,

    fn parse(allocator: Allocator) !Options {
        var args = try std.process.argsAlloc(allocator);
        errdefer std.process.argsFree(allocator, args);

        if (args.len == 0) {
            return error.ExecutableNameMissing;
        }
        const prog_name = std.fs.path.basename(args[0]);

        invalid: {
            if (args.len == 1) {
                std.log.err("Missing command", .{});
                break :invalid;
            }

            const command = name_to_command.get(args[1]) orelse {
                std.log.err("Invalid command '{s}'", .{args[1]});
                break :invalid;
            };

            if (command == .help) {
                try printHelp(prog_name);
                var opts: Options = undefined;
                opts.args = args;
                opts.command = command;
                return opts;
            }

            var verbose = false;
            var force = false;

            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const arg = args[i];
                if (std.mem.eql(u8, arg, "-v")) {
                    verbose = true;
                } else if (std.mem.eql(u8, arg, "-f")) {
                    force = true;
                } else {
                    std.log.err("Superficial positional argument '{s}'.", .{arg});
                    break :invalid;
                }
            }

            return Options{
                .args = args,
                .command = command,
                .verbose = verbose,
                .force = force,
                .modem_address = (try getEnvVar(allocator, "DUMPSTERFIRE_ADDRESS", null)) orelse break :invalid,
                .username = (try getEnvVar(allocator, "DUMPSTERFIRE_USERNAME", default_username)).?,
                .password = (try getEnvVar(allocator, "DUMPSTERFIRE_PASSWORD", null)) orelse break :invalid,
            };
        }

        std.log.err("See '{s} help'", .{prog_name});
        return error.InvalidArgs;
    }

    fn getEnvVar(allocator: Allocator, key: []const u8, maybe_default: ?[]const u8) !?[]const u8 {
        return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => if (maybe_default) |default|
                try allocator.dupe(u8, default)
            else {
                std.log.err("Missing required environent variable '{s}'", .{key});
                return null;
            },
            else => |others| return others,
        };
    }

    fn printHelp(prog_name: []const u8) !void {
        const stdout = std.io.getStdOut().writer();
        try stdout.print(
            \\Usage: {s} [command] [options]
            \\
            \\Utility to control Arris tg2492lg modems. Note, the modems are very slow,
            \\and so commands might take a few seconds to finish.
            \\
            \\Common Options:
            \\-v              Turn on debug logging.
            \\                Warning: Might log sensitive information!
            \\-f              Continue even if a web interface user is already logged in.
            \\                Warning: This logs out the current user.
            \\
            \\Common environment variables:
            \\DUMPSTERFIRE_ADDRESS     Modem web interface address.
            \\DUMPSTERFIRE_USERNAME    Modem login username. (optional, default: 'admin')
            \\DUMPSTERFIRE_PASSWORD    Modem login passowrd.
            \\
            \\Commands:
            \\help            Print this message and exit.
            \\status          Print generic modem status.
            \\wan-status      Print modem WAN status.
            \\logout-current  Log the current user out of the web interface.
            ,
            .{prog_name},
        );
    }

    fn deinit(self: Options, allocator: Allocator) void {
        std.process.argsFree(allocator, self.args);
        if (self.command != .help) {
            allocator.free(self.modem_address);
            allocator.free(self.username);
            allocator.free(self.password);
        }
    }
};

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var opts = Options.parse(allocator) catch |err| switch (err) {
        error.InvalidArgs, error.ExecutableNameMissing => return 1,
        else => |others| return others,
    };
    defer opts.deinit(allocator);
    if (opts.command == .help) {
        return 0;
    }

    log_verbose = opts.verbose;

    try run(allocator, opts);
    return 0;
}

fn run(allocator: Allocator, opts: Options) !void {
    var session = try Session.init(allocator, opts.modem_address);
    defer session.close();

    try session.login(opts.username, opts.password);

    const maybe_logged_in_type = session.alreadyLoggedInUserType() catch |err| switch (err) {
        error.NotLoggedIn => unreachable,
    };
    if (maybe_logged_in_type) |logged_in_type| {
        const name = switch (logged_in_type) {
            .local_user, .other_local_user => "local",
            .other_remote_user_terminatable, .other_remote_user => "remote",
            .unknown => "unknown",
        };

        std.log.debug("another {s} user is already logged in", .{ name });

        if (!opts.force and opts.command != .logout_current) {
            std.log.err("Another {s} user is currently already logged in.", .{ name });
            std.log.err("Rerun this command with -f to forcibly log them out.", .{});
            return;
        }
    }

    const maybe_err = runCommand(allocator, opts, session);

    // Try to log out even if an error occurred while running the command.
    session.logout() catch |err| switch (err) {
        error.NotLoggedIn => unreachable,
        error.Unauthorized => {},
        else => |other| if (maybe_err) |_| {
            return other;
        } else |original_err| {
            std.log.err("{} occurred after running command returned with error {}", .{other, original_err});
            return original_err;
        }
    };

    return maybe_err;
}

fn runCommand(allocator: Allocator, opts: Options, session: *Session) !void {
    const stdout = std.io.getStdOut().writer();

    switch (opts.command) {
        .help => unreachable,
        .status => {
            const status = try session.modemStatus(allocator);
            defer status.deinit(allocator);
            try status.dump(stdout);
        },
        .wan_status => {
            const wan_status = try session.wanStatus(allocator);
            try wan_status.dump(stdout);
        },
        .logout_current => {},
    }
}
