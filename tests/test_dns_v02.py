import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from recon.models import DnsQueryResult, DnsQueryStatus, DnsRecord, DnssecStatus
from recon.modules import DnsCollector, DnssecCollector
from tests.test_dns import TABLE, client

S = DnsQueryStatus


def q(name, rtype, status=S.NOERROR, values=(), ad=None):
    return DnsQueryResult(name=name, record_type=rtype, status=status, response_time_ms=1,
                          records=[DnsRecord(value=v) for v in values], authenticated=ad)


def rsa_key_b64(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    return base64.b64encode(key.public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


async def test_spf_lookup_counting_follows_includes_and_counts_void():
    table = dict(TABLE)
    table[("example.com", "TXT")] = ['"v=spf1 include:a.test include:b.test mx a -all"']
    table[("a.test", "TXT")] = ['"v=spf1 include:c.test ip4:1.2.3.4 ~all"']
    table[("c.test", "TXT")] = ['"v=spf1 a mx exists:%{i}.x.test -all"']
    table[("b.test", "TXT")] = ['"not spf"']            # void: no SPF record
    data, _ = await DnsCollector("example.com", client(table)).collect()
    spf = data.email.spf
    # include:a(1) → include:c(1) → a,mx,exists(3) ; include:b(1) ; mx, a (2)  = 8
    assert spf.lookup_count == 8 and spf.void_lookups == 1 and spf.lookup_limit_exceeded is False
    assert any(line.startswith("include:a.test (+4") for line in spf.lookup_tree)
    assert any("void lookup" in line for line in spf.lookup_tree)


async def test_spf_limit_exceeded_and_loop_detection():
    table = dict(TABLE)
    table[("example.com", "TXT")] = ['"v=spf1 ' + " ".join(f"include:i{n}.test" for n in range(11)) + ' -all"']
    for n in range(11):
        table[(f"i{n}.test", "TXT")] = ['"v=spf1 include:example.com -all"']   # loops back
    data, _ = await DnsCollector("example.com", client(table)).collect()
    spf = data.email.spf
    assert spf.lookup_limit_exceeded is True and spf.lookup_count > 10
    assert any("loop" in e for e in spf.evaluation_errors)


def test_spf_parse_errors_and_ptr():
    rec = DnsCollector.parse_spf_record("v=spf1 ip4 inclde:x.com include: ptr exp=explain.%{d} foo=bar -all")
    assert rec.uses_ptr is True and rec.all_qualifier == "-"
    assert any("ip4 without argument" in e for e in rec.parse_errors)
    assert any("unknown mechanism" in e for e in rec.parse_errors)
    assert any("include without argument" in e for e in rec.parse_errors)
    assert not any("exp" in e or "foo" in e for e in rec.parse_errors)   # unknown modifiers are allowed


async def test_dmarc_alignment_tags_and_dkim_key_parsing():
    table = dict(TABLE)
    table[("_dmarc.example.com", "TXT")] = ['"v=DMARC1; p=reject; adkim=s; aspf=r; fo=1; rua=mailto:x@y.z"']
    key2048 = rsa_key_b64(2048)
    key1024 = rsa_key_b64(1024)
    table[("selector1._domainkey.example.com", "TXT")] = [f'"v=DKIM1; k=rsa; t=s; p={key2048[:200]}" "{key2048[200:]}"']
    table[("selector2._domainkey.example.com", "TXT")] = [f'"v=DKIM1; p={key1024}"']
    table[("k1._domainkey.example.com", "TXT")] = ['"v=DKIM1; p="']
    data, _ = await DnsCollector("example.com", client(table), ("selector1", "selector2", "k1", "s1")).collect()
    d = data.email.dmarc
    assert (d.adkim, d.aspf, d.fo, d.policy) == ("s", "r", "1", "reject")
    keys = {k.selector: k for k in data.email.dkim_found}
    assert keys["selector1"].key_bits == 2048 and keys["selector1"].tags["t"] == "s"
    assert keys["selector2"].key_bits == 1024
    assert keys["k1"].revoked is True and keys["k1"].key_bits is None
    assert "s1" not in keys and data.email.dkim_selectors_checked == ["selector1", "selector2", "k1", "s1"]


async def test_caa_is_inherited_from_parent():
    table = dict(TABLE)
    table[("example.com", "CAA")] = ['0 issue "letsencrypt.org"']
    collector = DnsCollector("shop.example.com", client(table))
    data, _ = await collector.collect()
    caa = data.caa
    assert caa.effective_name == "example.com" and caa.inherited is True
    assert caa.records == ['0 issue "letsencrypt.org"']
    assert caa.checked == {"shop.example.com": "NXDOMAIN", "example.com": "NOERROR"} or \
        list(caa.checked) == ["shop.example.com", "example.com"]


async def test_caa_absent_everywhere_and_inconclusive():
    data, _ = await DnsCollector("example.com", client(TABLE)).collect()
    assert data.caa.effective_name is None and data.caa.complete is True
    import dns.exception
    table = dict(TABLE)
    table[("example.com", "CAA")] = dns.exception.Timeout()
    data, _ = await DnsCollector("example.com", client(table)).collect()
    assert data.caa.complete is False


async def test_www_cname_is_queried():
    table = dict(TABLE)
    table[("www.example.com", "CNAME")] = ["cname.vercel-dns.com."]
    data, _ = await DnsCollector("example.com", client(table)).collect()
    assert data.queries["CNAME(www)"].values == ["cname.vercel-dns.com"]


@pytest.mark.parametrize("ds, dnskey, ad, expected", [
    ((S.NOERROR, ["1 13 2 ab"]), (S.NOERROR, ["257 3 13 key"]), True, DnssecStatus.SIGNED_VALIDATED),
    ((S.NOERROR, ["1 13 2 ab"]), (S.NOERROR, ["257 3 13 key"]), False, DnssecStatus.SIGNED_UNVALIDATED),
    ((S.NODATA, []), (S.NODATA, []), False, DnssecStatus.UNSIGNED),
    ((S.NODATA, []), (S.NOERROR, ["257 3 13 key"]), False, DnssecStatus.ISLAND),
    ((S.NOERROR, ["1 13 2 ab"]), (S.NODATA, []), False, DnssecStatus.BROKEN),
    ((S.TIMEOUT, []), (S.NOERROR, ["257 3 13 key"]), True, DnssecStatus.UNKNOWN),
])
def test_dnssec_classification_uses_all_signals(ds, dnskey, ad, expected):
    result = DnssecCollector.classify(q("x.com", "DS", ds[0], ds[1]), q("x.com", "DNSKEY", dnskey[0], dnskey[1]),
                                      q("x.com", "SOA", S.NOERROR, ["ns. admin. 1 2 3 4 5"], ad=ad))
    assert result is expected


async def test_dnssec_collector_reads_algorithms():
    class Stub:
        async def query(self, name, rtype):
            return {"DS": q(name, "DS", S.NOERROR, ["2371 13 2 ABCDEF"]),
                    "DNSKEY": q(name, "DNSKEY", S.NOERROR, ["257 3 13 AAAA", "256 3 13 BBBB"]),
                    "SOA": q(name, "SOA", S.NOERROR, ["ns. a. 1 2 3 4 5"], ad=True)}[rtype]

    data, errors = await DnssecCollector("www.example.com", Stub()).collect()
    assert data.zone == "example.com" and data.status is DnssecStatus.SIGNED_VALIDATED
    assert data.key_algorithms == ["ECDSAP256SHA256"] and data.ds_digest_types == ["SHA-256"]
    assert data.dnskey_count == 2 and errors == []
