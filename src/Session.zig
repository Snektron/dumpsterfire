const std = @import("std");
const hzzp = @import("hzzp");
const oid = @import("oid.zig");
const ar = @import("ar.zig");
const mib2 = @import("mib2.zig");

const Stream = std.net.Stream;
const Address = std.net.Address;
const base64 = std.base64.standard;
const log = std.log.scoped(.session);
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const assert = std.debug.assert;
const epoch = std.time.epoch;

const Session = @This();

// TODO Uri-safe encoding where required.

const AlreadyLoggedInUser = enum(u8) {
    local_user = 1,
    other_remote_user_terminatable = 2,
    other_local_user = 3,
    other_remote_user = 4,
    unknown,
};

const port = 80;
const buffer_size = 4096;

const BufferedWriter = std.io.BufferedWriter(buffer_size, Stream.Writer);
const BufferedReader = std.io.BufferedReader(buffer_size, Stream.Reader);
const ResponseParser = hzzp.parser.response.ResponseParser(BufferedReader.Reader);

// Note: Field names reflect json structure in credential.
const Attrs = struct {
    unique: []const u8,
    family: []const u8,
    modelname: []const u8,
    name: []const u8,
    tech: bool,
    moca: u32,
    wifi: u32,
    conType: []const u8,
    muti: ?[]const u8 = null,
    gwWan: []const u8,
    DefPasswdChanged: []const u8,
};

allocator: *Allocator,

host: []const u8,
stream: Stream,
br: BufferedReader,
bw: BufferedWriter,
response_buffer: [buffer_size]u8,
response_parser: ResponseParser,
full_response_buffer: std.ArrayListUnmanaged(u8),

nonce: u32,

credential: ?[]const u8,

// Contents only valid if credential is not null.
attrs: Attrs,

pub fn init(allocator: *Allocator, host: []const u8) !*Session {
    log.debug("connecting to modem at {s}:{}", .{host, port});

    const stream = try std.net.tcpConnectToHost(allocator, host, port);
    errdefer stream.close();

    var self = try allocator.create(Session);
    errdefer allocator.free(self);

    self.allocator = allocator;
    self.host = host;
    self.stream = stream;
    self.br = .{.unbuffered_reader = self.stream.reader()};
    self.bw = .{.unbuffered_writer = self.stream.writer()};
    self.response_parser = ResponseParser.init(&self.response_buffer, self.br.reader());
    self.response_parser.done = true; // To make drainResponse work on the first request.
    self.full_response_buffer = .{};

    self.refreshNonce();
    self.credential = null;

    return self;
}

pub fn close(self: *Session) void {
    const allocator = self.allocator;
    self.full_response_buffer.deinit(self.allocator);
    if (self.credential) |credential| {
        allocator.free(credential);
        std.json.parseFree(Attrs, self.attrs, .{.allocator = self.allocator});
    }
    self.stream.close();
    allocator.destroy(self);
}

const Response = struct {
    status: u16,
    data: []const u8,
};

// Return value is valid until the next call to get()
fn get(self: *Session, endpoint: []const u8, query_params: anytype) !Response {
    self.response_parser.reset();

    var writer = self.bw.writer();

    try writer.writeAll("GET ");
    try writer.writeAll(endpoint);
    try writer.writeByte('?');

    // Note: Some query parameters need to be before the nonce
    inline for (std.meta.fields(@TypeOf(query_params))) |field, i| {
        if (i != 0) {
            try writer.writeByte('&');
        }
        try writer.writeAll(field.name ++ "=");
        const value = @field(query_params, field.name);
        switch (field.field_type) {
            []const u8, []u8 => try writer.writeAll(value),
            oid.Scalar => try writer.print("{s}.{};", .{value.oid, value.index}),
            []const oid.Scalar, []oid.Scalar => {
                for (value) |item| {
                    try writer.print("{s}.{};", .{item.oid, item.index});
                }
            },
            oid.Vector => try writer.print("{s}", .{value.oid}),
            []const oid.Vector, []oid.Vector => {
                for (value) |item| {
                    try writer.print("{s};", .{item.oid});
                }
            },
            else => @compileError("Invalid query parameter type " ++ @typeName(field.field_type)),
        }
    }

    if (std.meta.fields(@TypeOf(query_params)).len > 0) {
        try writer.writeByte('&');
    }
    try writer.print("_n={}", .{ self.nonce });

    try writer.print(" HTTP/1.1\r\nHost: {s}\r\n", .{self.host});
    if (self.credential) |c| {
        try writer.print("Cookie: credential={s}\r\n", .{c});
    }
    try writer.writeAll("\r\n");
    try self.bw.flush();

    self.full_response_buffer.items.len = 0;
    var status: u16 = undefined;

    const payload = while (try self.response_parser.next()) |event| {
        switch (event) {
            .status => |e| status = e.code,
            .payload => |e| {
                if (e.final and self.full_response_buffer.items.len == 0)
                    break e.data;

                try self.full_response_buffer.appendSlice(self.allocator, e.data);

                if (e.final) {
                    break self.full_response_buffer.items;
                }
            },
            else => {},
        }
    } else &[_]u8{};

    return Response{.status = status, .data = payload};
}

fn checkHasCredential(self: Session) !void {
    if (self.credential == null) return error.NotLoggedIn;
}

pub fn refreshNonce(self: *Session) void {
    var prng = std.rand.DefaultPrng.init(@bitCast(u64, std.time.milliTimestamp()));
    // Modem nonce consists of 5 digits in the original implementation.
    self.nonce = prng.random.intRangeLessThan(u32, 10_000, 100_000);
    log.debug("nonce: {}", .{ self.nonce });
}

pub fn login(self: *Session, username: []const u8, password: []const u8) !void {
    if (self.credential) |credential| {
        self.allocator.free(credential);
        std.json.parseFree(Attrs, self.attrs, .{.allocator = self.allocator});
    }

    const arg_plain = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ username, password });
    defer self.allocator.free(arg_plain);

    const arg = try self.allocator.alloc(u8, base64.Encoder.calcSize(arg_plain.len));
    defer self.allocator.free(arg);
    _ = base64.Encoder.encode(arg, arg_plain);

    const response = try self.get("/login", .{.arg = arg});
    if (response.status != 200) {
        log.debug("failed to login, got status {}", .{ response.status });
        return error.LoginFailed;
    } else if (std.mem.eql(u8, response.data, "LockedOut")) {
        return error.LockedOut;
    }

    self.credential = try self.allocator.dupe(u8, response.data);
    log.debug("login successful, got credential {s}", .{ self.credential.? });
    try self.decodeCredential();
}

fn decodeCredential(self: *Session) !void {
    var plain_credential = try self.allocator.alloc(u8, try base64.Decoder.calcSizeForSlice(self.credential.?));
    defer self.allocator.free(plain_credential);
    try base64.Decoder.decode(plain_credential, self.credential.?);

    log.debug("plain credential: {s}", .{plain_credential});

    @setEvalBranchQuota(10000);
    var tokens = std.json.TokenStream.init(plain_credential);
    self.attrs = try std.json.parse(Attrs, &tokens, .{ .allocator = self.allocator });
}

pub fn alreadyLoggedInUserType(self: Session) !?AlreadyLoggedInUser {
    try self.checkHasCredential();

    const muti = self.attrs.muti orelse return null;

    const is_gw_wan = std.mem.eql(u8, self.attrs.gwWan, "t");
    const contype_is_lan = std.mem.eql(u8, self.attrs.conType, "LAN");
    const muti_is_gw_wan = std.mem.eql(u8, muti, "GW_WAN");
    const muti_is_lan = std.mem.eql(u8, muti, "LAN");

    if (!is_gw_wan and contype_is_lan and muti_is_gw_wan) {
        return AlreadyLoggedInUser.local_user;
    } else if (is_gw_wan and muti_is_lan) {
        return AlreadyLoggedInUser.other_remote_user_terminatable;
    } else if (!is_gw_wan and contype_is_lan and muti_is_lan) {
        return AlreadyLoggedInUser.other_local_user;
    } else if (is_gw_wan and muti_is_gw_wan) {
        return AlreadyLoggedInUser.other_remote_user;
    } else {
        return AlreadyLoggedInUser.unknown;
    }
}

pub fn logout(self: *Session) !void {
    try self.checkHasCredential();
    const response = try self.get("/logout", .{});
    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 500) {
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }
}

fn expectJsonToken(expected: std.meta.Tag(std.json.Token), maybe_actual: ?std.json.Token) !void {
    const actual = maybe_actual orelse return error.UnexpectedResponse;
    if (actual != expected) return error.UnexpectedResponse;
}

pub const QueryResult = struct {
    arena: ArenaAllocator.State,
    results: [][]u8,

    pub fn deinit(self: QueryResult, allocator: *Allocator) void {
        self.arena.promote(allocator).deinit();
    }
};

pub fn queryOids(self: *Session, ra: *Allocator, items: []const oid.Scalar) !QueryResult {
    assert(items.len >= 1);
    try self.checkHasCredential();
    const response = try self.get("/snmpGet", .{
        .oids = items
    });

    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 200 ){
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }

    if (std.mem.startsWith(u8, response.data, "query returned Error in OID formatting!")) {
        log.err("query oid was formatted incorrectly", .{});
        unreachable; // If the server returned the above error, there was a bug in this program.
    }

    var arena = ArenaAllocator.init(ra);
    errdefer arena.deinit();

    const results = try arena.allocator.alloc([]u8, items.len);

    // We don't really need a full JSON parser here. The result will look like `{<oid>:<value>[, <oid>:<value>]?}`.
    var tokens = std.json.TokenStream.init(response.data);

    // For now, assume that the result is ordered the same as the query.
    try expectJsonToken(.ObjectBegin, try tokens.next());
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        try expectJsonToken(.String, try tokens.next());
        const tok = try tokens.next();
        try expectJsonToken(.String, tok);

        const text = tok.?.String.slice(response.data, tokens.i - 1);
        const decoded_length = tok.?.String.decodedLength();

        results[i] = try arena.allocator.alloc(u8, decoded_length);
        try std.json.unescapeValidString(results[i], text);
    }
    try expectJsonToken(.ObjectEnd, try tokens.next());

    return QueryResult{
        .arena = arena.state,
        .results = results
    };
}

pub const WalkResult = struct {
    const Entry = struct {
        keys: [][]u8,
        values: [][]u8,
    };

    arena: ArenaAllocator.State,
    results: []Entry,

    pub fn deinit(self: WalkResult, allocator: *Allocator) void {
        self.arena.promote(allocator).deinit();
    }
};

pub fn walk(self: *Session, ra: *Allocator, vectors: []const oid.Vector) !WalkResult {
    assert(vectors.len >= 1);
    try self.checkHasCredential();
    const response = try self.get("/walk", .{
        .oids = vectors
    });

    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 200) {
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }

    var arena = ArenaAllocator.init(ra);
    errdefer arena.deinit();

    const results = try arena.allocator.alloc(WalkResult.Entry, vectors.len);
    var current_list = std.MultiArrayList(struct{ key: []u8, value: []u8 }){};

    // We don't really need a full JSON parser here. The result will look like `{<oid>:<value>[, <oid>:<value>]?}`.
    var tokens = std.json.TokenStream.init(response.data);

    // For now, assume that the result is ordered the same as the query.
    try expectJsonToken(.ObjectBegin, try tokens.next());
    var i: usize = 0;
    while (true) {
        const key_tok = try tokens.next();
        try expectJsonToken(.String, key_tok);
        const key_text = key_tok.?.String.slice(response.data, tokens.i - 1);
        const key_dlen = key_tok.?.String.decodedLength();

        const val_tok = try tokens.next();
        try expectJsonToken(.String, val_tok);
        const val_text = val_tok.?.String.slice(response.data, tokens.i - 1);
        const val_dlen = val_tok.?.String.decodedLength();

        // We don't expect any escapes in the initial oid part of the key at least, so check
        // that without allocating.

        if (!std.mem.startsWith(u8, key_text, vectors[i].oid)) {
            const slice = current_list.toOwnedSlice();
            results[i].keys = slice.items(.key);
            results[i].values = slice.items(.value);
            i += 1;

            if (i == vectors.len) {
                if (!std.mem.eql(u8, key_text, "1") or !std.mem.eql(u8, val_text, "Finish")) {
                    return error.UnexpectedResponse;
                }

                try expectJsonToken(.ObjectEnd, try tokens.next());
                break;
            }
        }

        const key = try arena.allocator.alloc(u8, key_dlen - vectors[i].oid.len);
        const val = try arena.allocator.alloc(u8, val_dlen);

        try std.json.unescapeValidString(key, key_text[vectors[i].oid.len..]);
        try std.json.unescapeValidString(val, val_text);

        try current_list.append(&arena.allocator, .{.key = key, .value = val});
    }

    return WalkResult{
        .arena = arena.state,
        .results = results,
    };
}

const Status = struct {
    arena: ArenaAllocator.State,

    admin_timeout: u64,
    tz_utc_offset: i8,
    language: []u8,
    modem_name: []u8,
    serial_number: []u8,
    hardware_version: []u8,
    firmware_version: []u8,
    current_time: oid.Date,
    uptime: oid.Duration,
    cable_mac: oid.MacAddress,

    pub fn deinit(self: Status, ra: *Allocator) void {
        self.arena.promote(ra).deinit();
    }

    pub fn dump(self: Status, writer: anytype) !void {
        try writer.print("admin timeout: {}\n", .{ self.admin_timeout });
        try writer.print("timezone utc offset: {}\n", .{ self.tz_utc_offset });
        try writer.print("language: {s}\n", .{ self.language });
        try writer.print("modem name: {s}\n", .{ self.modem_name });
        try writer.print("serial number: {s}\n", .{ self.serial_number });
        try writer.print("hardware version: {s}\n", .{ self.hardware_version });
        try writer.print("firmware version: {s}\n", .{ self.firmware_version });
        try writer.print("current time: {}\n", .{ self.current_time });
        try writer.print("uptime: {}\n", .{ self.uptime });
        try writer.print("cable mac address: {}\n", .{ self.cable_mac });
    }
};

pub fn modemStatus(self: *Session, ra: *Allocator) !Status {
    const result = try self.queryOids(ra, &.{
        ar.sys_cfg.admin_timeout,
        ar.sys_cfg.time_zone_utc_offset,
        ar.sys_cfg.language,
        ar.sys_cfg.name,
        ar.sys_cfg.serial_number,
        ar.sys_cfg.boot_code_version,
        ar.sys_cfg.hardware_version,
        ar.sys_cfg.firmware_version,
        ar.sys_cfg.current_time,
        mib2.system.uptime,
        mib2.interfaces.if_table.if_entry.phys_address.at(2),
    });
    errdefer result.deinit(ra);
    const results = result.results;

    return Status{
        .arena = result.arena,
        .admin_timeout = try std.fmt.parseInt(u64, results[0], 10),
        .tz_utc_offset = try std.fmt.parseInt(i8, results[1], 10),
        .language = results[2],
        .modem_name = results[3],
        .serial_number = results[4],
        .hardware_version = results[5],
        .firmware_version = results[7],
        .current_time = try oid.Date.parse(results[8]),
        .uptime = try oid.Duration.parse(results[9]),
        .cable_mac = try oid.MacAddress.parse(results[10]),
    };
}

const WanStatus = struct {
    mac: oid.MacAddress,
    address_type: enum { v6, v4 },
    ipv4: struct {
        address: oid.Ipv4Address,
        prefix: u5,
        default_gateway: oid.Ipv4Address,
        lease_time: oid.Duration,
        lease_expire: oid.Date,
    },
    ipv6: struct {
        address: oid.Ipv6Address,
        prefix: u7,
        default_gateway: oid.Ipv6Address,
        lease_time: oid.Duration,
        lease_expire: oid.Date,
    },

    pub fn dump(self: WanStatus, writer: anytype) !void {
        try writer.print("mac: {}\n", .{ self.mac });
        try writer.print("ip type: {s}\n", .{ @tagName(self.address_type) });
        try writer.print("ipv4 address: {}/{}\n", .{ self.ipv4.address, self.ipv4.prefix });
        try writer.print("ipv4 default gateway: {}\n", .{ self.ipv4.address });
        try writer.print("ipv4 lease time: {}\n", .{ self.ipv4.lease_time });
        try writer.print("ipv4 lease expire: {}\n", .{ self.ipv4.lease_expire });
        try writer.print("ipv6 address: {}/{}\n", .{ self.ipv6.address, self.ipv6.prefix });
        try writer.print("ipv6 default gateway: {}\n", .{ self.ipv6.address });
        try writer.print("ipv6 lease time: {}\n", .{ self.ipv6.lease_time });
        try writer.print("ipv6 lease expire: {}\n", .{ self.ipv6.lease_expire });
    }
};

pub fn wanStatus(self: *Session, ra: *Allocator) !WanStatus {
    const result = try self.queryOids(ra, &.{
        ar.wan_config.if_mac_addr,
        ar.wan_config.v6,

        ar.wan_config.current_table.entry.ip_addr.at(1),
        ar.wan_config.current_table.entry.prefix.at(1),
        ar.wan_config.current_table.entry.gw.at(1),
        ar.wan_config.dhcp_objects.duration,
        ar.wan_config.dhcp_objects.expire,

        ar.wan_config.current_table.entry.ip_addr.at(2),
        ar.wan_config.current_table.entry.prefix.at(2),
        ar.wan_config.current_table.entry.gw.at(2),
        ar.wan_config.dhcp_objects.duration_v6,
        ar.wan_config.dhcp_objects.expire_v6,
    });
    defer result.deinit(ra);
    const results = result.results;

    return WanStatus{
        .mac = try oid.MacAddress.parse(results[0]),
        .address_type = if (std.mem.eql(u8, results[1], "1")) .v6 else .v4,
        .ipv4 = .{
            .address = try oid.Ipv4Address.parse(results[2]),
            .prefix = try std.fmt.parseInt(u5, results[3], 10),
            .default_gateway = try oid.Ipv4Address.parse(results[4]),
            .lease_time = try oid.Duration.parse(results[5]),
            .lease_expire = try oid.Date.parse(results[6]),
        },
        .ipv6 = .{
            .address = try oid.Ipv6Address.parse(results[7]),
            .prefix = try std.fmt.parseInt(u7, results[8], 10),
            .default_gateway = try oid.Ipv6Address.parse(results[9]),
            .lease_time = try oid.Duration.parse(results[10]),
            .lease_expire = try oid.Date.parse(results[11]),
        },
    };
}
