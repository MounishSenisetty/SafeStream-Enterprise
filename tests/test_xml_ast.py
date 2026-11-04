import xml.etree.ElementTree as ET

import pytest
from safestream_redactor import RedactionStats, Redactor

from safestream_enterprise import StructuredParseError, StructuredRedactor
from safestream_enterprise.parsers.xml_ast import MAX_DEPTH, looks_like_xml

R = StructuredRedactor()


def redact(doc: str | bytes) -> str:
    out = R.redact_line(doc)
    assert out.structured, out.text
    return out.text


WIN_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def test_windows_security_event() -> None:
    event = (
        f'<Event xmlns="{WIN_NS}"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
        "</System><EventData>"
        '<Data Name="TargetUserName">bob</Data>'
        '<Data Name="IpAddress">10.1.2.3</Data>'
        '<Data Name="LogonType">3</Data>'
        "</EventData></Event>"
    )
    assert "bob" in Redactor().redact(event)  # the OSS text path misses the username
    out = redact(event)
    # Default namespace kept as-is (the stdlib serialiser would write <ns0:Event ...>).
    assert out.startswith(f'<Event xmlns="{WIN_NS}"><System>')
    assert "<EventID>4624</EventID>" in out
    # Fields named by the Name attribute are redacted; the labels stay readable.
    assert '<Data Name="TargetUserName">[REDACTED]</Data>' in out
    assert '<Data Name="IpAddress">[REDACTED]</Data>' in out
    assert '<Data Name="LogonType">3</Data>' in out
    assert "bob" not in out and "10.1.2.3" not in out
    # (Provider's Name value is left to the OSS free-text tier, whose entropy
    # detector currently flags "Microsoft-Windows-Security-Auditing"; that is
    # the OSS engine's call, not this module's, so it is not asserted here.)


def test_element_and_attribute_rules_and_free_text() -> None:
    doc = (
        '<user id="7" email="bob@corp.example"><LastName>Smith</LastName>'
        "<Phone>555 0100</Phone><host>web-1</host>"
        "<msg>login by alice@corp.example</msg>"
        '<param key="password" value="hunter2"/></user>'
    )
    assert redact(doc) == (
        '<user id="7" email="[REDACTED]"><LastName>[REDACTED]</LastName>'
        "<Phone>[REDACTED]</Phone><host>web-1</host>"
        "<msg>login by [REDACTED]</msg>"
        '<param key="password" value="[REDACTED]"/></user>'
    )


def test_sensitive_element_redacts_whole_subtree_and_keeps_layout() -> None:
    doc = (
        '<r>\n  <Credentials kind="basic">\n    <user>u</user>\n'
        "    <pin>1234</pin>\n  </Credentials>\n  <ok>yes</ok>\n</r>"
    )
    assert redact(doc) == (
        '<r>\n  <Credentials kind="[REDACTED]">\n    <user>[REDACTED]</user>\n'
        "    <pin>[REDACTED]</pin>\n  </Credentials>\n  <ok>yes</ok>\n</r>"
    )


def test_tail_text_takes_parent_sensitivity() -> None:
    # "Smith" is a tail inside <LastName>; the tail after </b> belongs to <r>.
    assert redact("<r><LastName><b/>Smith</LastName>mail bob@corp.example</r>") == (
        "<r><LastName><b/>[REDACTED]</LastName>mail [REDACTED]</r>"
    )


def test_namespace_prefixes_survive_exactly() -> None:
    doc = (
        '<s:Envelope xmlns:s="urn:soap" xml:lang="en"><s:Body>'
        '<p:Auth xmlns:p="urn:p" p:password="x" p:realm="corp"/>'
        '<q xmlns="urn:q"><r xmlns="">plain</r></q>'
        "</s:Body></s:Envelope>"
    )
    assert redact(doc) == doc.replace('p:password="x"', 'p:password="[REDACTED]"')


def test_escaping_round_trips() -> None:
    doc = '<a t="say &quot;hi&quot; &amp; &lt;go&gt;&#10;">1 &lt; 2 &amp;&amp; 3 &gt; 2&#13;</a>'
    out = redact(doc)
    original, again = ET.fromstring(doc), ET.fromstring(out)
    assert (again.text, again.attrib) == (original.text, original.attrib)


def test_dropped_constructs_and_encodings() -> None:
    # Comments (which can hold PII), PIs and the declaration are dropped; CDATA is escaped.
    doc = '<?xml version="1.0"?><a><!-- ssn 123-45-6789 --><?pi x?><b><![CDATA[<i>]]></b></a>'
    assert redact(doc) == "<a><b>&lt;i&gt;</b></a>"
    assert redact(b"\xef\xbb\xbf  <name>Zo\xc3\xab</name>\n") == "<name>Zoë</name>"
    assert redact("<a>Zoë</a>".encode("utf-16-le")) == "<a>Zoë</a>"  # BOM-less UTF-16


@pytest.mark.parametrize(
    "hostile",
    [
        # billion laughs
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;">]><l>&b;</l>',
        # XXE: local file disclosure
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        # XXE via external DTD (SSRF)
        '<!DOCTYPE r SYSTEM "http://169.254.169.254/latest/meta-data/"><r/>',
    ],
)
def test_dtds_are_refused_in_every_encoding(hostile: str) -> None:
    for data in (hostile, hostile.encode(), hostile.encode("utf-16-le")):
        out = R.redact_line(data)
        assert not out.structured and "lollol" not in out.text and "root:" not in out.text
        with pytest.raises(StructuredParseError, match="document type declaration"):
            R.redact_line(data, strict=True)


def test_depth_bound_and_malformed() -> None:
    ok = "<a>" * MAX_DEPTH + "</a>" * MAX_DEPTH
    assert R.redact_line(ok).structured
    too_deep = "<a>" * (MAX_DEPTH + 1) + "</a>" * (MAX_DEPTH + 1)
    with pytest.raises(StructuredParseError, match="deeper"):
        R.redact_line(too_deep, strict=True)
    # Malformed XML falls back to the text engine, so its PII is still caught.
    out = R.redact_line("<a><b>mail bob@corp.example</a>")
    assert not out.structured and "bob@corp.example" not in out.text
    with pytest.raises(StructuredParseError, match="not well-formed") as info:
        R.redact_line("<a><b>hunter2</a>", strict=True)
    assert "hunter2" not in str(info.value)


def test_stats_and_detection() -> None:
    stats = RedactionStats()
    R.redact_line('<r><email>a</email><Data Name="Phone">1</Data><m>x@y.example</m></r>', stats)
    assert dict(stats.counts) == {"email": 2, "phone": 1}
    assert looks_like_xml(b" \n<a/>") and looks_like_xml("﻿<a/>")
    assert not looks_like_xml('{"a": "<b>"}') and not looks_like_xml(b"plain")
