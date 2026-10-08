-- Snort 3 configuration for running Snort alongside the ML detectors.
--
--   snort -c snort/nids.lua --include-path /etc/snort -r capture.pcap -l <log dir> -q
--
-- Builds on the stock snort_defaults.lua (found through --include-path) and
-- writes alert_json.txt with the fields the correlator needs to link each alert
-- to a flow: Unix time, addresses, ports and protocol.

HOME_NET = os.getenv('NIDS_HOME_NET') or 'any'
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

-- Do not drop packets with bad checksums. Network cards compute checksums in hardware
-- (offloading), so a capture on the sending machine — your own laptop's outgoing traffic,
-- or the CSE-CIC-IDS2018 servers' captures — holds packets whose checksum is not filled in
-- yet. Snort skipped them by default: on the 2018 web-attack capture (~40% such packets) it
-- raised no web-attack alert at all; ignoring checksums, it flags the attacks.
network = { checksum_eval = 'none' }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
normalizer = { }
http_inspect = { }
dns = { }
ssh = { }
ssl = { }
ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

-- Scans: the classic thing a signature IDS sees that per-flow ML features miss.
-- DNS servers answering many lookups look like a "UDP filtered portscan" to Snort,
-- so scan reports whose source is port 53 are ignored.
port_scan = default_med_port_scan
port_scan.ignore_scanners = '0.0.0.0/0#53'  -- CIDR#port

wizard = default_wizard
binder =
{
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { when = { service = 'dns' }, use = { type = 'dns' } },
    { when = { service = 'ssh' }, use = { type = 'ssh' } },
    { when = { service = 'ssl' }, use = { type = 'ssl' } },
    { when = { service = 'ftp' }, use = { type = 'ftp_server' } },
    { use = { type = 'wizard' } },
}

local rules_dir = os.getenv('NIDS_SNORT_RULES') or 'snort/rules'
local rules = 'include ' .. rules_dir .. '/nids.rules\n'

-- Snort 3 community rules (exploits, malware, C2, policy...), fetched by
-- ./start.sh setup into rules/community/; NIDS_SNORT_COMMUNITY=0 leaves them out.
local community = rules_dir .. '/community/snort3-community.rules'
local found = io.open(community)
if found then
    found:close()
    if os.getenv('NIDS_SNORT_COMMUNITY') ~= '0' then
        rules = rules .. 'include ' .. community .. '\n'
    end
end

ips =
{
    -- Inspectors' built-in alerts are mostly protocol anomalies (e.g. a TLS session seen
    -- from the middle), not attacks; nids.rules turns on just the port-scan ones (gid 122).
    enable_builtin_rules = false,
    rules = rules,
    variables = default_variables,
}

-- Community rules that report ordinary network behaviour, not attacks. With checksums
-- ignored they fired thousands of times on the dataset's normal workstation (e.g. 2,674
-- "DNS response with 1-minute TTL", ~1,500 pings and replies); ping sweeps are still
-- reported by the port_scan inspector. Policy rules (RDP, SMB) stay on: they flag exposure.
suppress =
{
    { gid = 1, sid = 254 },    -- PROTOCOL-DNS SPOOF query response with TTL of 1 min
    { gid = 1, sid = 366 },    -- PROTOCOL-ICMP PING Unix
    { gid = 1, sid = 368 },    -- PROTOCOL-ICMP PING BSDtype
    { gid = 1, sid = 384 },    -- PROTOCOL-ICMP PING
    { gid = 1, sid = 385 },    -- PROTOCOL-ICMP traceroute
    { gid = 1, sid = 402 },    -- PROTOCOL-ICMP destination unreachable port unreachable
    { gid = 1, sid = 404 },    -- PROTOCOL-ICMP Destination Unreachable Protocol Unreachable
    { gid = 1, sid = 408 },    -- PROTOCOL-ICMP Echo Reply
    { gid = 1, sid = 449 },    -- PROTOCOL-ICMP Time-To-Live Exceeded in Transit
    { gid = 1, sid = 459 },    -- PROTOCOL-ICMP unassigned type 1: misfires on IPv6 housekeeping
    { gid = 1, sid = 29456 },  -- PROTOCOL-ICMP Unusual PING detected
    { gid = 1, sid = 1917 },   -- INDICATOR-SCAN UPnP service discover attempt
}

alert_json =
{
    file = true,
    fields = 'seconds timestamp proto src_addr src_port dst_addr dst_port action class msg priority gid sid rev service',
}
