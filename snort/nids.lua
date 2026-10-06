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
port_scan = default_med_port_scan

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
ips =
{
    enable_builtin_rules = true,  -- inspector alerts, e.g. port_scan (gid 122)
    include = rules_dir .. '/nids.rules',
    variables = default_variables,
}

alert_json =
{
    file = true,
    fields = 'seconds timestamp proto src_addr src_port dst_addr dst_port action class msg priority gid sid rev service',
}
