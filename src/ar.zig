const oid = @import("oid.zig");
const scalar = oid.scalar;
const vector = oid.vector;

pub const wan_config = struct {
    pub const conn_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.1", 0);
    pub const host_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.2", 0);
    pub const domain_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.3", 0);
    pub const mtu_size = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.4", 0x42);
    pub const current_table = struct {
        pub const entry = struct {
            pub const ip_index = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.1", 0);
            pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.2", 0);
            pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.3", 0x4);
            pub const prefix = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.4", 0);
            pub const gw_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.5", 0);
            pub const gw = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.6", 0x4);
            pub const ip_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.7", 0);
            pub const net_mask = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.8", 0);
            pub const prefix_delegation_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.9", 0x4);
            pub const prefix_delegation_v6_len = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.10", 0x42);
            pub const preferred_lifetime_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.11", 0);
            pub const valid_lifetime_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.1.7.1.12", 0x2);
        };
    };
    pub const static_free_idx = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.8", 0);
    pub const static_table = struct {
        pub const entry = struct {
            pub const ip_index = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.1", 0);
            pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.2", 0);
            pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.3", 0);
            pub const prefix = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.4", 0);
            pub const gateway_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.5", 0);
            pub const gateway = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.6", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.7", 0);
            pub const delegated_prefix_length = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.8", 0);
            pub const delegated_prefix = vector("1.3.6.1.4.1.4115.1.20.1.1.1.9.1.9", 0);
        };
    };
    pub const tunnel_objects = struct {
        pub const user_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.1", 0);
        pub const password = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.2", 0);
        pub const enable_idle_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.3", 0);
        pub const idle_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.4", 0);
        pub const addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.5", 0);
        pub const addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.6", 0);
        pub const host_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.7", 0);
        pub const enable_keep_alive = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.8", 0);
        pub const keep_alive_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.10.9", 0);
    };
    pub const dns_objects = struct {
        pub const use_auto_dns = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.11.1", 0);
        pub const current_dns_table = struct {
            pub const entry = struct {
                pub const dnsip_index = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.1", 0);
                pub const dnsip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.2", 0x2);
                pub const dnsip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.2.1.3", 0x4);
            };
        };
        pub const static_dns_table = struct {
            pub const entry = struct {
                pub const dnsip_index = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.4.1.1", 0);
                pub const dnsip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.4.1.2", 0);
                pub const dnsip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.4.1.3", 0);
                pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.1.11.4.1.4", 0x2);
            };
        };
    };
    pub const dhcp_objects = struct {
        pub const renew_lease = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.1", 0);
        pub const release_lease = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.2", 0);
        pub const duration = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.3", 0x42);
        pub const expire = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.4", 0x4);
        pub const renew_lease_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.5", 0);
        pub const release_lease_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.6", 0);
        pub const duration_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.7", 0x42);
        pub const expire_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.8", 0x4);
        pub const dhcp_srv_ip_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.9", 0);
        pub const dhcp_opt43_sub02 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.10", 0);
        pub const dhcpduid_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.11", 0);
        pub const srv_addr_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.12", 0);
        pub const srv_duid_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.12.13", 0);
    };
    pub const if_mac_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.13", 0x4);
    pub const v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.16", 0);
    pub const ip_prov_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.17", 0x2);
    pub const ds_lite_wan_objects = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.1", 0x2);
        pub const lsnat_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.2", 0);
        pub const lsnat_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.3", 0);
        pub const tcp_mss_clamping = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.4", 0);
        pub const tcp_mss_value = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.5", 0);
        pub const resolved_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.18.6", 0x4);
    };
    pub const soft_gre_wan_objects = struct {
        pub const table = struct {
            pub const entry = struct {
                pub const enable = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.1", 0);
                pub const mapped_interface = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.2", 0);
                pub const max_sessions = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.3", 0);
                pub const controller_fqdn = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.4", 0);
                pub const controller_provisioned_secondary_ip_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.5", 0);
                pub const controller_provisioned_secondary_ip_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.6", 0);
                pub const failover_ping_count = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.7", 0);
                pub const failover_ping_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.8", 0);
                pub const failover_threshold = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.9", 0);
                pub const circuit_id_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.10", 0);
                pub const remote_id_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.11", 0);
                pub const radius_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.12", 0);
                pub const radius_server_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.13", 0);
                pub const radius_server_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.14", 0);
                pub const radius_server_port = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.15", 0);
                pub const radius_key = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.16", 0);
                pub const radius_re_auth_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.17", 0);
                pub const vlan_q_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.18", 0);
                pub const dscp = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.19", 0);
                pub const dns_retry_timer = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.20", 0);
                pub const current_controller_ip_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.21", 0);
                pub const current_controller_ip_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.22", 0);
                pub const primary_controller_ip_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.23", 0);
                pub const primary_controller_ip_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.24", 0);
                pub const secondary_controller_ip_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.25", 0);
                pub const secondary_controller_ip_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.26", 0);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.27", 0);
                pub const transport_interface = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.29", 0);
                pub const radius_transport_interface = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.30", 0);
                pub const acct_server_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.31", 0);
                pub const acct_server_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.32", 0);
                pub const acct_server_port = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.33", 0);
                pub const acct_key = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.34", 0);
                pub const acct_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.35", 0);
                pub const radius_secondary_server_address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.36", 0);
                pub const radius_secondary_server_address = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.37", 0);
                pub const radius_secondary_server_port = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.38", 0);
                pub const radius_secondary_key = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.39", 0);
                pub const radius_secondary_re_auth_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.1.1.40", 0);
            };
        };
        pub const ssid_table = struct {
            pub const entry = struct {
                pub const v_lan_id = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.2.1.1", 0);
                pub const v_lan_priority = vector("1.3.6.1.4.1.4115.1.20.1.1.1.19.2.1.2", 0);
            };
        };
        pub const customer_opt_out = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.19.3", 0);
        pub const capable = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.19.5", 0);
    };
    pub const dhcp_relay_agent_wan_objects = struct {
        pub const ssid_table = struct {
            pub const entry = struct {
                pub const enable = vector("1.3.6.1.4.1.4115.1.20.1.1.1.20.1.1.1", 0);
                pub const circuit_id_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.20.1.1.2", 0);
                pub const remote_id_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.20.1.1.3", 0);
                pub const option60_ssid_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.1.20.1.1.4", 0);
            };
        };
    };
    pub const t_r181_gateway_info_objects = struct {
        pub const t_r181_gateway_manufacturer_oui = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.21.1", 0);
        pub const t_r181_gateway_product_class = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.21.2", 0);
        pub const t_r181_gateway_serial_number = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.21.3", 0);
    };
    pub const force_igmp_version = scalar("1.3.6.1.4.1.4115.1.20.1.1.1.22", 0);
};
pub const lan_config = struct {
    pub const srv_table = struct {
        pub const entry = struct {
            pub const name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.1", 0x4);
            pub const subnet_mask_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.2", 0);
            pub const subnet_mask = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.3", 0x4);
            pub const gateway_ip_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.4", 0);
            pub const gateway_ip = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.5", 0x4);
            pub const gateway_ip2_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.6", 0);
            pub const gateway_ip2 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.7", 0x4);
            pub const v_lan_id = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.8", 0);
            pub const use_dhcp = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.9", 0x2);
            pub const start_dhcp_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.10", 0);
            pub const start_dhcp = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.11", 0x4);
            pub const end_dhcp_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.12", 0);
            pub const end_dhcp = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.13", 0x4);
            pub const lease_time = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.14", 0x42);
            pub const domain_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.15", 0);
            pub const relay_dns = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.19", 0);
            pub const pass_thru = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.21", 0);
            pub const firewall_on = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.22", 0);
            pub const u_pn_p_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.23", 0x2);
            pub const cpe_aging = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.24", 0);
            pub const override_dns = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.25", 0);
            pub const nat_algs_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.26", 0);
            pub const mapped_interface = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.27", 0);
            pub const environment_control = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.28", 0);
            pub const prefix_length_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.29", 0x42);
            pub const use_dhcp_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.30", 0x2);
            pub const start_dhcp_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.31", 0x4);
            pub const end_dhcp_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.32", 0x4);
            pub const lease_time_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.33", 0x42);
            pub const link_local_address_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.34", 0);
            pub const dns_relay_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.35", 0);
            pub const dns_override_v6 = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.36", 0);
            pub const pre_prov_lease_time = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.37", 0);
            pub const parental_controls_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.2.2.1.39", 0x2);
        };
    };
    pub const dns_table = struct {
        pub const entry = struct {
            pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.3.1.1", 0);
            pub const dnsip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.3.1.2", 0);
            pub const dnsip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.2.3.1.3", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.3.1.4", 0x2);
        };
    };
    pub const client_objects = struct {
        pub const lan_client_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.4.1", 0);
        pub const lan_client_table = struct {
            pub const entry = struct {
                pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.1", 0);
                pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.2", 0x4);
                pub const host_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3", 0x4);
                pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4", 0x4);
                pub const adapter_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.6", 0x2);
                pub const @"type" = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.7", 0x2);
                pub const lease_end = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.9", 0x4);
                pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.13", 0x2);
                pub const online = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.14", 0x2);
                pub const comment = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.15", 0x4);
                pub const manufacturer_oui = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.17", 0);
                pub const serial_number = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.18", 0);
                pub const product_class = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.19", 0);
                pub const device_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.20", 0x4);
                pub const last_change = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.24", 0);
                pub const time_connected = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.25", 0);
            };
        };
        pub const device_up_down_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.3.1.1", 0);
                pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.3.1.2", 0);
                pub const ip_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.3.1.3", 0);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.3.1.7", 0x2);
            };
        };
        pub const lan_custom_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.4.4", 0);
        pub const lan_custom_table = struct {
            pub const entry = struct {
                pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.1", 0);
                pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.2", 0);
                pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.3", 0);
                pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.4", 0);
                pub const friend_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.5", 0);
                pub const host_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.6", 0);
                pub const mac_mfg = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.7", 0);
                pub const comments = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.8", 0);
                pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.5.1.9", 0x2);
            };
        };
        pub const lan_client_dhcp_options_table = struct {
            pub const entry = struct {
                pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.8.1.1", 0);
                pub const tag = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.8.1.2", 0);
                pub const value = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.8.1.3", 0);
                pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.4.8.1.4", 0);
            };
        };
    };
    pub const rip_objects = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.1", 0);
        pub const auth_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.2", 0);
        pub const report_time = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.3", 0);
        pub const auth_key_string = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.4", 0);
        pub const auth_key_id = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.5", 0);
        pub const ripip_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.6", 0);
        pub const ripip_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.7", 0);
        pub const prefix_len = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.8", 0);
        pub const auth_key_chain = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.9", 0);
        pub const routed_subnet_ip_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.10", 0);
        pub const routed_subnet_ip = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.11", 0);
        pub const routed_subnet_gw_net_ip_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.12", 0);
        pub const routed_subnet_gw_net_ip = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.13", 0);
        pub const routed_subnet_mask = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.14", 0);
        pub const routed_subnet_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.15", 0);
        pub const send_cm_interface = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.16", 0);
        pub const routed_subnet_dhcp = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.17", 0);
        pub const routed_subnet_nat = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.5.18", 0);
    };
    pub const settings = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.6", 0);
    pub const ether_port_table = struct {
        pub const entry = struct {
            pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.1", 0);
            pub const if_index = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.2", 0);
            pub const enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.3", 0x2);
            pub const duplex = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.4", 0);
            pub const speed = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.5", 0x2);
            pub const auto = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.6", 0);
            pub const has_link = vector("1.3.6.1.4.1.4115.1.20.1.1.2.8.1.7", 0);
        };
    };
    pub const ri_png_objects = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.1", 0);
        pub const addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.2", 0);
        pub const subnet_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.3", 0);
        pub const routed_subnet_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.4", 0);
        pub const routed_subnet_prefix_length = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.5", 0);
        pub const send_cm_interface = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.9.6", 0);
    };
    pub const srv_dhcp_options_table = struct {
        pub const entry = struct {
            pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.1", 0);
            pub const enable = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.2", 0);
            pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.3", 0);
            pub const tag = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.4", 0);
            pub const value = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.5", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.11.1.6", 0);
        };
    };
    pub const max_i_pv6_ra_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.13", 0x42);
    pub const min_i_pv6_ra_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.14", 0);
    pub const bridge_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.15", 0);
    pub const usb_port_table = struct {
        pub const entry = struct {
            pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.1", 0);
            pub const has_link = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.2", 0);
            pub const descr = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.3", 0);
            pub const serial_num = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.4", 0);
            pub const speed = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.5", 0);
            pub const manuf = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.6", 0);
            pub const storage_nam = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.7", 0);
            pub const file_sys = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.8", 0);
            pub const space_avail = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.9", 0);
            pub const total_space = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.10", 0);
            pub const usb_port_folders_file = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.11", 0);
            pub const del_storage = vector("1.3.6.1.4.1.4115.1.20.1.1.2.16.1.12", 0);
        };
    };
    pub const file_sharing_objs = struct {
        pub const filesharing_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.17.1", 0);
        pub const filesharing_dev_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.17.2", 0);
        pub const table = struct {
            pub const entry = struct {
                pub const filesharing_idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.1", 0);
                pub const filesharing_row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.2", 0);
                pub const filesharing_usb_port = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.3", 0);
                pub const filesharing_directory = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.4", 0);
                pub const filesharing_name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.5", 0);
                pub const filesharing_enable_http = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.6", 0);
                pub const filesharing_enable_ftp = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.7", 0);
                pub const filesharing_visibility = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.8", 0);
                pub const filesharing_every_one_perm = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.9", 0);
                pub const filesharing_desc = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.3.1.10", 0);
            };
        };
        pub const local_user_table = struct {
            pub const entry = struct {
                pub const idx = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.4.1.1", 0);
                pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.4.1.2", 0);
                pub const name = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.4.1.3", 0);
                pub const passwd = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.4.1.4", 0);
            };
        };
        pub const filesharing_permit_table = struct {
            pub const entry = struct {
                pub const permitvalue = vector("1.3.6.1.4.1.4115.1.20.1.1.2.17.5.1.1", 0);
            };
        };
    };
    pub const i_pv6_ra_lifetime = scalar("1.3.6.1.4.1.4115.1.20.1.1.2.19", 0x42);
};
pub const wireless_cfg = struct {
    pub const wi_fi_country = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.1", 0x4);
    pub const wi_fi_channel = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.2", 0x42);
    pub const wi_fi_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.3", 0x2);
    pub const wi_fi_bg_protect = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.4", 0);
    pub const wi_fi_beacon_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.5", 0);
    pub const wi_fi_dtim_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.6", 0);
    pub const wi_fi_tx_preamble = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.7", 0);
    pub const wi_fi_rts_threshold = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.8", 0);
    pub const wi_fi_fragment_thresh = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.9", 0);
    pub const wi_fi_short_slot = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.10", 0);
    pub const wi_fi_frame_burst = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.11", 0);
    pub const wi_fi_enable_radio = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.12", 0x2);
    pub const wi_fi_short_retry_limit = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.14", 0);
    pub const wi_fi_long_retry_limit = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.15", 0);
    pub const wi_fi_output_power = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.16", 0);
    pub const wi_fi80211_n_settings = struct {
        pub const band = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.1", 0);
        pub const fi_htmcs = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.2", 0);
        pub const fi_channel_bw = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.3", 0x2);
        pub const side_band = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.4", 0);
        pub const fi_ht_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.5", 0);
        pub const fi_guard_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.6", 0);
        pub const fi_decline_peer_ba = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.8", 0);
        pub const fi_block_ack = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.9", 0);
        pub const fi_n_protection = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.10", 0);
        pub const fi_allow40_m_hz_only_operation = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.21.11", 0x2);
    };
    pub const bss_table = struct {
        pub const entry = struct {
            pub const bss_id = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.1", 0x4);
            pub const bss_ssid = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2", 0x4);
            pub const bss_active = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.3", 0x2);
            pub const bss_ssid_broadcast = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.4", 0x2);
            pub const bss_security_mode = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5", 0x2);
            pub const bss_access_mode = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.6", 0x2);
            pub const bss_network_isolate = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.7", 0);
            pub const bss_mac_access_count = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.8", 0);
            pub const bss_mac_access_clear = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.9", 0);
            pub const arp_audit_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.10", 0);
            pub const bss_max_wifi_clients = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.11", 0);
            pub const bss_wmm_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.12", 0);
            pub const bss_wmm_apsd = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.13", 0);
            pub const bss_active_timeout = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.14", 0x4);
            pub const default_bss_ssid = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.15", 0x4);
            pub const bss_sta_steering_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.3.22.1.16", 0);
        };
    };
    pub const wep_table = struct {
        pub const entry = struct {
            pub const current_key = vector("1.3.6.1.4.1.4115.1.20.1.1.3.23.1.1", 0);
            pub const encryption_mode = vector("1.3.6.1.4.1.4115.1.20.1.1.3.23.1.2", 0);
        };
    };
    pub const we_p64_bit_key_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.24.1.1", 0);
            pub const value = vector("1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2", 0);
            pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.3.24.1.3", 0x2);
        };
    };
    pub const we_p128_bit_key_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.25.1.1", 0);
            pub const value = vector("1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2", 0);
            pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.3.25.1.3", 0x2);
        };
    };
    pub const wpa_table = struct {
        pub const entry = struct {
            pub const algorithm = vector("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1", 0x2);
            pub const pre_shared_key = vector("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2", 0x4);
            pub const re_auth_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.4", 0);
            pub const pre_auth_enable = vector("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.5", 0);
            pub const default_wpa_pre_shared_key = vector("1.3.6.1.4.1.4115.1.20.1.1.3.26.1.6", 0x4);
        };
    };
    pub const radius_table = struct {
        pub const entry = struct {
            pub const address_type = vector("1.3.6.1.4.1.4115.1.20.1.1.3.27.1.1", 0);
            pub const address = vector("1.3.6.1.4.1.4115.1.20.1.1.3.27.1.2", 0);
            pub const port = vector("1.3.6.1.4.1.4115.1.20.1.1.3.27.1.3", 0);
            pub const key = vector("1.3.6.1.4.1.4115.1.20.1.1.3.27.1.4", 0);
            pub const re_auth_interval = vector("1.3.6.1.4.1.4115.1.20.1.1.3.27.1.5", 0);
        };
    };
    pub const mac_access_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.28.1.1", 0);
            pub const addr = vector("1.3.6.1.4.1.4115.1.20.1.1.3.28.1.2", 0x4);
            pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.3.28.1.3", 0x2);
            pub const device_name = vector("1.3.6.1.4.1.4115.1.20.1.1.3.28.1.4", 0x4);
        };
    };
    pub const wmm_cfg = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.29.1", 0);
        pub const no_ack = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.29.2", 0);
        pub const wmmapsd = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.29.3", 0);
        pub const wmmedcaap_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.1", 0);
                pub const wmmedcaapc_wmin = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.2", 0);
                pub const wmmedcaapc_wmax = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.3", 0);
                pub const wmmedcaapaifsn = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.4", 0);
                pub const tx_op_b_limit = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.5", 0);
                pub const tx_op_ag_limit = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.6", 0);
                pub const admit_cont = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.7", 0);
                pub const discard_old = vector("1.3.6.1.4.1.4115.1.20.1.1.3.29.4.1.8", 0);
            };
        };
    };
    pub const wps_cfg = struct {
        pub const wps_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.1", 0x2);
        pub const wps_config_state = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.2", 0);
        pub const wps_device_pin = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.3", 0x4);
        pub const wps_device_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.4", 0);
        pub const wps_model_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.5", 0);
        pub const wps_mfg = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.6", 0);
        pub const wps_result_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.7", 0x2);
        pub const wps_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.8", 0);
        pub const wps_config_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.9", 0);
        pub const wps_sta_pin = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.10", 0x4);
        pub const wps_push_button = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.11", 0x2);
        pub const wps_uuid = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.14", 0);
        pub const method_cfg = struct {
            pub const label = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.15.1", 0);
            pub const pin = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.15.2", 0x2);
            pub const push_button = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.15.3", 0x2);
            pub const keypad = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.30.15.4", 0);
        };
    };
    pub const wi_fi_reset_defaults = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.32", 0);
    pub const wi_fi_custom_ssid_str = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.34", 0);
    pub const wi_fi_radio_control_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.37", 0x2);
    pub const wi_fi_scan = struct {
        pub const start_scan = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.39.1", 0);
        pub const result = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.39.2", 0);
        pub const result_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.1", 0);
                pub const ssid = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.2", 0);
                pub const channel = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.3", 0);
                pub const channel2 = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.4", 0);
                pub const rssi = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.5", 0);
                pub const noise = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.6", 0);
                pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.7", 0);
                pub const mfg = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.8", 0);
                pub const supported_rates = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.9", 0);
                pub const operating_standards = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.10", 0);
                pub const security_mode_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.11", 0);
                pub const operating_channel_bandwidth = vector("1.3.6.1.4.1.4115.1.20.1.1.3.39.3.1.12", 0);
            };
        };
    };
    pub const wi_fi_client_info_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.1", 0);
            pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.2", 0);
            pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.3", 0);
            pub const ip_addr_textual = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.4", 0x4);
            pub const host_name = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.5", 0x4);
            pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.6", 0x4);
            pub const mac_mfg = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.7", 0);
            pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.8", 0);
            pub const first_seen = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.9", 0);
            pub const last_seen = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.10", 0);
            pub const idle_time = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.11", 0);
            pub const in_network_time = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.12", 0);
            pub const state = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.13", 0);
            pub const flags = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.14", 0);
            pub const tx_pkts = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.15", 0);
            pub const tx_failures = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.16", 0);
            pub const rx_unicast_pkts = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.17", 0);
            pub const rx_multicast_pkts = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.18", 0);
            pub const last_tx_pkt_rate = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.19", 0);
            pub const last_rx_pkt_rate = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.20", 0x2);
            pub const rate_set = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.21", 0);
            pub const rssi = vector("1.3.6.1.4.1.4115.1.20.1.1.3.42.1.22", 0x2);
        };
    };
    pub const wi_fi_physical_channel = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.43", 0x2);
    pub const wi_fi50_radio_settings = struct {
        pub const channel = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.1", 0x42);
        pub const mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.2", 0x2);
        pub const beacon_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.3", 0);
        pub const dtim_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.4", 0);
        pub const tx_preamble = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.5", 0);
        pub const rts_threshold = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.6", 0);
        pub const fragment_thresh = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.7", 0);
        pub const short_slot = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.8", 0);
        pub const frame_burst = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.9", 0);
        pub const enable_radio = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.10", 0x2);
        pub const short_retry_limit = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.12", 0);
        pub const long_retry_limit = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.13", 0);
        pub const output_power = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.14", 0);
        pub const multicast_a = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.15", 0);
        pub const physical_channel = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.16", 0x2);
        pub const n_settings = struct {
            pub const htmcs = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.1", 0);
            pub const channel_bw = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.2", 0x2);
            pub const side_band = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.3", 0);
            pub const ht_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.4", 0);
            pub const guard_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.5", 0);
            pub const amsdu_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.6", 0);
            pub const decline_peer_ba = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.7", 0);
            pub const block_ack = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.8", 0);
            pub const protection = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.20.9", 0);
        };
        pub const ht_tx_stream = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.21", 0);
        pub const ht_rx_stream = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.22", 0);
        pub const enable_stbc = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.23", 0);
        pub const enable_rdg = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.24", 0);
        pub const igmp_snooping = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.25", 0);
        pub const block_dfs_chan = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.26", 0);
        pub const rts_retry = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.27", 0);
        pub const tx_retry = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.50.28", 0);
    };
    pub const wi_fi_num_ssid_supported = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.51", 0);
    pub const wi_fi_ht_tx_stream = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.55", 0);
    pub const wi_fi_ht_rx_stream = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.56", 0);
    pub const wi_fi_enable_stbc = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.57", 0);
    pub const wi_fi_enable_rdg = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.58", 0);
    pub const wi_fi_igmp_snooping = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.59", 0);
    pub const wi_fi_rts_retry = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.60", 0);
    pub const wi_fi_tx_retry = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.61", 0);
    pub const wi_fi_physical_channel_stats = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.62.1", 0);
        pub const measurement_rate = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.62.2", 0);
        pub const measurement_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.62.3", 0);
        pub const channel_stats_measurement_table = struct {
            pub const entry = struct {
                pub const min_noise_floor = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.1", 0);
                pub const max_noise_floor = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.2", 0);
                pub const median_noise_floor = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.3", 0);
                pub const packets_sent = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.4", 0);
                pub const packets_received = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.5", 0);
                pub const cst_exceed_percent = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.6", 0);
                pub const activity_factor = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.7", 0);
                pub const channel_utilization = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.8", 0);
                pub const retransmissions_metric = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.4.1.9", 0);
            };
        };
        pub const channel_stats_rssi_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.5.1.1", 0);
                pub const count = vector("1.3.6.1.4.1.4115.1.20.1.1.3.62.5.1.2", 0);
            };
        };
    };
    pub const wm_m50_cfg = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.63.1", 0);
        pub const no_ack = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.63.2", 0);
        pub const apsd = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.63.3", 0);
        pub const edcaap_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.1", 0);
                pub const edcaapc_wmin = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.2", 0);
                pub const edcaapc_wmax = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.3", 0);
                pub const edcaapaifsn = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.4", 0);
                pub const tx_op_b_limit = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.5", 0);
                pub const tx_op_ag_limit = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.6", 0);
                pub const admit_cont = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.7", 0);
                pub const discard_old = vector("1.3.6.1.4.1.4115.1.20.1.1.3.63.4.1.8", 0);
            };
        };
    };
    pub const wi_fi_extension_channel = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.64", 0);
    pub const wp_s50_cfg = struct {
        pub const wps50_mode = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.1", 0x2);
        pub const wps50_config_state = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.2", 0);
        pub const wps50_device_pin = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.3", 0x4);
        pub const wps50_device_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.4", 0);
        pub const wps50_model_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.5", 0);
        pub const wps50_mfg = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.6", 0);
        pub const wps50_result_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.7", 0x2);
        pub const wps50_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.8", 0);
        pub const wps50_config_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.9", 0);
        pub const wps50_sta_pin = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.10", 0x4);
        pub const wps50_push_button = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.11", 0x2);
        pub const wps50_uuid = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.65.14", 0);
    };
    pub const wifi_low_init_rate = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.66", 0);
    pub const wi_fi_bss_sta_steering = struct {
        pub const reset = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.69.1", 0);
        pub const deny_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.69.2", 0);
        pub const deny_window = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.69.3", 0);
        pub const bss_sta_steering_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.4.1.1", 0);
                pub const table_clear = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.4.1.2", 0);
                pub const table_deny_count = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.4.1.3", 0);
                pub const table_deny_window = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.4.1.4", 0);
                pub const table_status = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.4.1.5", 0);
            };
        };
        pub const bss_sta_steering_client_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.5.1.1", 0);
                pub const mac_address = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.5.1.2", 0);
                pub const last_assoc_time = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.5.1.3", 0);
                pub const other_bss_joined_count = vector("1.3.6.1.4.1.4115.1.20.1.1.3.69.5.1.4", 0);
            };
        };
    };
    pub const wi_fi_interworking_ie = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.70", 0);
    pub const airtime_ctrl_cfg = struct {
        pub const bssid_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.3.99.1", 0);
        pub const bssid_weight_table = struct {
            pub const entry = struct {
                pub const guaranteed_percentage = vector("1.3.6.1.4.1.4115.1.20.1.1.3.99.2.1.1", 0);
                pub const maximum_percentage = vector("1.3.6.1.4.1.4115.1.20.1.1.3.99.2.1.2", 0);
            };
        };
    };
};
pub const fw_cfg = struct {
    pub const enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.1", 0x2);
    pub const enable_dmz = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.6", 0x2);
    pub const fwip_addr_type_dmz = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.7", 0);
    pub const fwip_addr_dmz = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.8", 0x4);
    pub const security_level = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.9", 0);
    pub const virt_srv_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.1", 0);
            pub const desc = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.2", 0x4);
            pub const port_start = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.3", 0x42);
            pub const port_end = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.4", 0x42);
            pub const proto_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.5", 0x2);
            pub const ip_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.6", 0x2);
            pub const ip_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.7", 0x4);
            pub const local_port_start = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.9", 0x42);
            pub const local_port_end = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.10", 0x42);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.11", 0x2);
            pub const srv_tr69_instance_id = vector("1.3.6.1.4.1.4115.1.20.1.1.4.12.1.14", 0);
        };
    };
    pub const fwip_filter_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.1", 0);
            pub const desc = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.2", 0);
            pub const start_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.3", 0);
            pub const start_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.4", 0);
            pub const end_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.5", 0);
            pub const end_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.6", 0);
            pub const port_start = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.7", 0);
            pub const port_end = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.8", 0);
            pub const proto_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.9", 0);
            pub const tod = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.10", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.11", 0x2);
            pub const action = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.12", 0);
            pub const direction = vector("1.3.6.1.4.1.4115.1.20.1.1.4.13.1.13", 0);
        };
    };
    pub const allow_all = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.14", 0);
    pub const fwmac_filter_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.15.1.1", 0);
            pub const addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.15.1.2", 0x4);
            pub const tod = vector("1.3.6.1.4.1.4115.1.20.1.1.4.15.1.3", 0x2);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.15.1.4", 0x2);
        };
    };
    pub const port_trig_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.1", 0);
            pub const desc = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.2", 0x4);
            pub const port_start = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.3", 0x42);
            pub const port_end = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.4", 0x42);
            pub const targ_port_start = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.5", 0x42);
            pub const targ_port_end = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.6", 0x42);
            pub const proto_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.7", 0x2);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.16.1.9", 0x2);
        };
    };
    pub const filter_rules = struct {
        pub const block_frag_ip_pkts = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.6", 0);
        pub const port_scan_protect = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.7", 0);
        pub const fwip_flood_detect = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.8", 0);
        pub const block_frag_ip_pkts_v4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.9", 0x2);
        pub const port_scan_protect_v4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.10", 0x2);
        pub const fwip_flood_detect_v4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.11", 0x2);
        pub const block_frag_ip_pkts_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.12", 0x2);
        pub const port_scan_protect_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.13", 0x2);
        pub const fwip_flood_detect_v6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.17.14", 0x2);
    };
    pub const fwddns_objs = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.1", 0x2);
        pub const @"type" = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.2", 0x2);
        pub const user_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.3", 0x4);
        pub const password = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.4", 0x4);
        pub const domain_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.5", 0x4);
        pub const fwddnsip_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.6", 0);
        pub const fwddnsip_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.7", 0);
        pub const status = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.18.8", 0x4);
    };
    pub const features = struct {
        pub const fwip_sec_pass_thru = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.2", 0);
        pub const fwpptp_pass_thru = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.3", 0);
        pub const enable_multicast = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.4", 0);
        pub const enable_remote_mgmt = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.5", 0);
        pub const l2_tp_pass_thru = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.7", 0);
        pub const remote_mgmt = struct {
            pub const http = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.1", 0);
            pub const https = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.2", 0x2);
            pub const http_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.3", 0);
            pub const https_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.4", 0x2);
            pub const allowed_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.5", 0);
            pub const allowed_i_pv4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.6", 0);
            pub const allowed_i_pv6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.7", 0);
            pub const allowed_start_i_pv4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.8", 0);
            pub const allowed_end_i_pv4 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.9", 0);
            pub const allowed_start_i_pv6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.10", 0);
            pub const allowed_end_i_pv6 = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.11", 0);
            pub const telnet = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.12.12", 0);
        };
        pub const select_remote_mgmt = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.19.13", 0);
    };
    pub const parental_controls = struct {
        pub const keyword_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.1", 0x2);
        pub const black_list_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.3", 0x2);
        pub const white_list_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.5", 0);
        pub const keyword_blk_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.10.1.1", 0);
                pub const word = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.10.1.2", 0x4);
                pub const tod = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.10.1.3", 0x2);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.10.1.4", 0x2);
            };
        };
        pub const black_list_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.12.1.1", 0);
                pub const domain = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.12.1.2", 0x4);
                pub const tod = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.12.1.3", 0x2);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.12.1.4", 0x2);
            };
        };
        pub const white_list_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.14.1.1", 0);
                pub const domain = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.14.1.2", 0);
                pub const tod = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.14.1.3", 0);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.14.1.4", 0x2);
            };
        };
        pub const trusted_device_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.1", 0);
                pub const mac = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.2", 0);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.3", 0x2);
                pub const name = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.4", 0);
                pub const addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.5", 0);
                pub const addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.16.1.6", 0);
            };
        };
        pub const enable_parental_cont = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.17", 0x2);
        pub const list_active_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.22", 0x2);
        pub const exception_list_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.20.24", 0x2);
        pub const exception_list_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.25.1.1", 0);
                pub const domain = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.25.1.2", 0x4);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.20.25.1.3", 0x2);
            };
        };
    };
    pub const allow_icmp = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.21", 0);
    pub const virt_srv_table_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.32", 0);
    pub const port_trig_table_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.33", 0);
    pub const fwi_pv6_security = struct {
        pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.40.7", 0x2);
    };
    pub const mac_bridging_web_page_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.41", 0);
    pub const mac_bridging_function_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.42", 0);
    pub const mac_bridging_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.43.1.1", 0);
            pub const name = vector("1.3.6.1.4.1.4115.1.20.1.1.4.43.1.2", 0);
            pub const mac_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.4.43.1.3", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.43.1.4", 0x2);
        };
    };
    pub const port_allow_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.4.44.1.1", 0);
            pub const inbound_port = vector("1.3.6.1.4.1.4115.1.20.1.1.4.44.1.2", 0);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.4.44.1.3", 0);
        };
    };
    pub const srv_tr69_last_instance = scalar("1.3.6.1.4.1.4115.1.20.1.1.4.46", 0);
};
pub const sys_cfg = struct {
    pub const admin_password = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.1", 0);
    pub const admin_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.2", 0);
    pub const time_zone_utc_offset = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.3", 0);
    pub const reboot = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.4", 0x2);
    pub const defaults = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.5", 0x2);
    pub const language = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.6", 0x4);
    pub const name = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.7", 0);
    pub const serial_number = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.8", 0x4);
    pub const boot_code_version = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.9", 0);
    pub const hardware_version = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.10", 0x4);
    pub const firmware_version = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.11", 0x4);
    pub const log_level = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.12", 0);
    pub const custom_settings = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.13", 0x4);
    pub const custom_id = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.14", 0x2);
    pub const current_time = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.15", 0x4);
    pub const auth_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.1", 0);
            pub const user_name = vector("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.2", 0x4);
            pub const password = vector("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.3", 0);
            pub const @"type" = vector("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.4", 0);
            pub const account_enabled = vector("1.3.6.1.4.1.4115.1.20.1.1.5.16.1.6", 0x2);
        };
    };
    pub const sntp_settings = struct {
        pub const enable_sntp = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.17.1", 0);
        pub const server_table = struct {
            pub const entry = struct {
                pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.17.4.1.1", 0);
                pub const addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.5.17.4.1.2", 0);
                pub const addr = vector("1.3.6.1.4.1.4115.1.20.1.1.5.17.4.1.3", 0);
                pub const name = vector("1.3.6.1.4.1.4115.1.20.1.1.5.17.4.1.4", 0);
                pub const status = vector("1.3.6.1.4.1.4115.1.20.1.1.5.17.4.1.5", 0x2);
            };
        };
    };
    pub const email_settings = struct {
        pub const server_name = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.1", 0);
        pub const server_user = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.2", 0);
        pub const server_pw = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.3", 0);
        pub const address = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.4", 0x4);
        pub const enable_log_email = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.5", 0);
        pub const apply_settings = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.6", 0x2);
        pub const sender_address = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.8", 0);
        pub const send = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.18.9", 0x2);
    };
    pub const log_settings = struct {
        pub const user_logs = struct {
            pub const firewall_log_table = struct {
                pub const entry = struct {
                    pub const fw_log_index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.1.1.1", 0);
                    pub const fw_log_time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.1.1.2", 0);
                    pub const fw_log_info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.1.1.3", 0);
                };
            };
            pub const parental_cont_log_table = struct {
                pub const entry = struct {
                    pub const pc_log_index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.2.1.1", 0);
                    pub const pc_log_time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.2.1.2", 0);
                    pub const pc_log_info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.2.1.3", 0);
                    pub const pc_log_type = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.2.1.4", 0);
                };
            };
            pub const change_log_table = struct {
                pub const entry = struct {
                    pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.3.1.1", 0);
                    pub const time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.3.1.2", 0);
                    pub const info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.3.1.3", 0);
                };
            };
            pub const debug_log_table = struct {
                pub const entry = struct {
                    pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.4.1.1", 0);
                    pub const time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.4.1.2", 0);
                    pub const info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.4.1.3", 0);
                };
            };
            pub const firewall_log_ext_table = struct {
                pub const entry = struct {
                    pub const fw_log_ext_index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.7.1.1", 0);
                    pub const fw_log_latest_event_time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.7.1.2", 0);
                    pub const fw_log_latest_event_info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.7.1.3", 0);
                    pub const fw_log_event_count = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.1.7.1.4", 0);
                };
            };
        };
        pub const mso_logs = struct {
            pub const chg_log_table = struct {
                pub const entry = struct {
                    pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.2.1.1.1", 0);
                    pub const time = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.2.1.1.2", 0);
                    pub const info = vector("1.3.6.1.4.1.4115.1.20.1.1.5.19.2.1.1.3", 0);
                };
            };
            pub const clear_mso_logs = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.19.2.2", 0x2);
        };
        pub const clear_logs = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.19.3", 0x2);
    };
    pub const tacacs_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.20", 0);
    pub const tacacs_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.21", 0);
    pub const tacacs_secret_key = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.22", 0);
    pub const xml_provisioning_file = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.23", 0);
    pub const xml_provisioning_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.24", 0);
    pub const inbound_traffic_log_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.34", 0);
    pub const inbound_traffic_log_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.5.42.1.1", 0);
            pub const data = vector("1.3.6.1.4.1.4115.1.20.1.1.5.42.1.2", 0);
        };
    };
    pub const wireless_band = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.55", 0x4);
    pub const save_current_config_file = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.57", 0x2);
    pub const restore_current_config_file = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.58", 0x2);
    pub const local_posix_time_zone = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.59", 0);
    pub const first_install_wizard_completion_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.62", 0x2);
    pub const troubleshooter_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.63", 0);
    pub const csr_active_timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.5.65", 0);
};
pub const host_access = struct {
    pub const web_access_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.6.7.1.1", 0);
            pub const page = vector("1.3.6.1.4.1.4115.1.20.1.1.6.7.1.2", 0x4);
            pub const level = vector("1.3.6.1.4.1.4115.1.20.1.1.6.7.1.3", 0x2);
            pub const row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.6.7.1.4", 0x2);
        };
    };
    pub const web_access_wanacl = scalar("1.3.6.1.4.1.4115.1.20.1.1.6.8", 0);
};
pub const ping_mgmt = struct {
    pub const target_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.1", 0x2);
    pub const target_address = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.2", 0x4);
    pub const num_pkts = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.3", 0x42);
    pub const pkt_size = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.4", 0x42);
    pub const interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.5", 0);
    pub const timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.6", 0);
    pub const verify_reply = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.7", 0);
    pub const ip_stack_number = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.8", 0);
    pub const start_stop = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.9", 0x2);
    pub const pkts_sent = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.10", 0);
    pub const replies_received = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.11", 0x41);
    pub const replies_verified = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.12", 0);
    pub const octets_sent = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.13", 0);
    pub const octets_received = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.14", 0);
    pub const icmp_errors = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.15", 0);
    pub const last_icmp_error = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.16", 0);
    pub const average_rtt = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.17", 0);
    pub const min_rtt = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.18", 0);
    pub const max_rtt = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.19", 0);
    pub const target_dns_query_ip_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.20", 0x2);
    pub const log = scalar("1.3.6.1.4.1.4115.1.20.1.1.7.21", 0x4);
};
pub const trace_rt_mgmt = struct {
    pub const targ_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.1", 0x2);
    pub const target_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.2", 0x4);
    pub const max_hops = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.3", 0x2);
    pub const data_size = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.4", 0x2);
    pub const resolve_hosts = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.5", 0);
    pub const base_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.6", 0x2);
    pub const start = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.7", 0x2);
    pub const log = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.8", 0x4);
    pub const timeout = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.9", 0);
    pub const diff_serv = scalar("1.3.6.1.4.1.4115.1.20.1.1.8.10", 0);
};
pub const apply_all_settings = scalar("1.3.6.1.4.1.4115.1.20.1.1.9", 0x2);
pub const i_ctrl = struct {
    pub const port_map_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.1", 0);
    pub const port_map_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.1", 0);
            pub const port_map_description = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.2", 0);
            pub const port_map_internal_client_addr_type = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.3", 0);
            pub const port_map_internal_client_addr = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.4", 0);
            pub const port_map_protocol = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.5", 0);
            pub const port_map_external_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.6", 0);
            pub const port_map_internal_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.7", 0);
            pub const port_map_row_status = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.8", 0);
            pub const port_map_internal_start_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.9", 0);
            pub const port_map_internal_end_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.10", 0);
            pub const port_map_external_start_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.11", 0);
            pub const port_map_external_end_port = vector("1.3.6.1.4.1.4115.1.20.1.1.10.2.1.12", 0);
        };
    };
    pub const get_device_settings = struct {
        pub const device_settings_f_wversion = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.3.1", 0);
    };
    pub const is_device_ready = struct {
        pub const device_status = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.4.1", 0);
    };
    pub const reboot = struct {
        pub const initiate_reboot = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.5.1", 0);
    };
    pub const set_device_settings = struct {
        pub const name = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.6.1", 0);
        pub const admin_password = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.6.2", 0);
    };
    pub const router_settings = struct {
        pub const manage_remote = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.7.1", 0);
        pub const remote_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.7.2", 0);
        pub const remote_ssl = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.7.3", 0);
    };
    pub const w_lan_radio_settings = struct {
        pub const mac_address = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.8.1", 0);
        pub const channel_width = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.8.2", 0);
    };
    pub const set_bridge_connect = struct {
        pub const ethernet_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.9.1", 0);
        pub const minutes = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.9.2", 0);
        pub const permanent_port4_enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.9.3", 0);
    };
    pub const get_wan_settings = struct {
        pub const @"type" = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.2", 0);
        pub const mtu = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.3", 0);
        pub const prefix_len = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.4", 0);
        pub const gateway_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.5", 0);
        pub const gateway_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.6", 0);
        pub const dns_primary_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.7", 0);
        pub const dns_primary_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.8", 0);
        pub const dns_secondary_addr_type = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.9", 0);
        pub const dns_secondary_addr = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.10", 0);
        pub const mac_address = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.10.11", 0);
    };
    pub const hnap_server_port = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.11", 0);
    pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.12", 0);
    pub const hashing_key = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.13", 0);
    pub const port_map_table_enabled = scalar("1.3.6.1.4.1.4115.1.20.1.1.10.14", 0);
};
pub const flap_list_cfg = struct {
    pub const enable = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.1", 0);
    pub const wlan_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.2", 0);
    pub const dhcp_interval = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.3", 0);
    pub const report_peroid = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.4", 0);
    pub const wlan_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.5", 0);
    pub const lan_count = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.6", 0);
    pub const req_freq_threshold = scalar("1.3.6.1.4.1.4115.1.20.1.1.11.7", 0);
    pub const wlan_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.11.10.1.1", 0);
            pub const mac_address = vector("1.3.6.1.4.1.4115.1.20.1.1.11.10.1.2", 0);
            pub const remove_time = vector("1.3.6.1.4.1.4115.1.20.1.1.11.10.1.3", 0);
            pub const flap_time = vector("1.3.6.1.4.1.4115.1.20.1.1.11.10.1.4", 0);
        };
    };
    pub const lan_table = struct {
        pub const entry = struct {
            pub const index = vector("1.3.6.1.4.1.4115.1.20.1.1.11.11.1.1", 0);
            pub const mac_address = vector("1.3.6.1.4.1.4115.1.20.1.1.11.11.1.2", 0);
            pub const remove_time = vector("1.3.6.1.4.1.4115.1.20.1.1.11.11.1.3", 0);
            pub const flap_time = vector("1.3.6.1.4.1.4115.1.20.1.1.11.11.1.4", 0);
        };
    };
};
