import ipaddress

from nids.services.reputation import Blocklist, load_blocklists


def make(ranges):
    bl = Blocklist()
    for cidr, source in ranges:
        bl.add(ipaddress.ip_network(cidr), source)
    return bl.finalize()


def test_check_matches_cidr_and_exact():
    bl = make([("203.0.113.0/24", "listA"), ("198.51.100.7/32", "listB")])
    assert bl.check("203.0.113.55") == "listA"
    assert bl.check("198.51.100.7") == "listB"
    assert bl.check("8.8.8.8") is None


def test_check_handles_overlapping_and_nested_ranges():
    bl = make([("10.0.0.0/8", "wide"), ("10.1.2.0/24", "narrow")])
    # both the wide and the narrow range cover this; any match is a hit
    assert bl.check("10.1.2.3") in ("wide", "narrow")
    assert bl.check("10.9.9.9") == "wide"


def test_ipv6_and_junk_are_ignored():
    bl = make([("203.0.113.0/24", "listA")])
    assert bl.check("2001:db8::1") is None
    assert bl.check("not-an-ip") is None


def test_load_blocklists_reads_files_and_skips_comments(tmp_path):
    (tmp_path / "firehol.netset").write_text("# comment\n203.0.113.0/24\n\n198.51.100.1\n")
    (tmp_path / "ignore.md").write_text("1.2.3.4\n")  # wrong extension
    bl = load_blocklists(tmp_path)
    assert len(bl) == 2
    assert bl.check("203.0.113.9") == "firehol"
    assert bl.check("198.51.100.1") == "firehol"
    assert bl.check("1.2.3.4") is None  # .md not loaded


def test_missing_directory_is_empty(tmp_path):
    assert len(load_blocklists(tmp_path / "nope")) == 0
