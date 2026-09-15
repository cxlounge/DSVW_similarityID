#!/usr/bin/env python3

"""End-to-end checks that every entry of 'dsvw.CASES' really behaves as advertised.

All third-party targets (httpbin.org, pastebin.com, geekprank.com, CUPS on :631) are replaced by
a local fixture, or asserted on without ever leaving the box.
"""

import html
import importlib.util
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture
import harness

sys.path.insert(0, harness.ROOT)
import dsvw

HAS_LXML = importlib.util.find_spec("lxml") is not None
POSIX = os.name != "nt"

server = None
fixture_server = None
fixture_url = None


def setUpModule():
    global server, fixture_server, fixture_url
    fixture_server, fixture_url = fixture.start()
    server = harness.Dsvw()
    assert server.started, "dsvw.py failed to start:\n%s" % server.output()


def tearDownModule():
    if server:
        server.cleanup()
    if fixture_server:
        fixture_server.shutdown()


def expect(code=200, contains=(), absent=(), min_elapsed=None, skip=None):
    return {"code": code, "contains": contains, "absent": absent, "min_elapsed": min_elapsed, "skip": skip}


def cases():
    """Maps plain case name -> (vulnerable url, exploit url) with HTML-escaping and href junk removed."""
    result = {}
    for name, vulnerable, exploit, info in dsvw.CASES:
        urls = []
        for url in (vulnerable, exploit):
            urls.append(None if url is None else html.unescape(url.split('"')[0]))
        result[harness.plain(name)] = tuple(urls)
    return result


def expectations():
    return {
        "Blind SQL Injection (boolean)": {
            "vuln": expect(contains=["<td>dricci</td>"]),
            "expl": expect(contains=["<td>dricci</td>"]),               # first character of admin's password really is '7'
        },
        "Blind SQL Injection (time)": {
            "vuln": expect(contains=["<td>dricci</td>"]),
            "expl": expect(contains=["Result(s)"], absent=["dricci"], min_elapsed=0.5),
        },
        "UNION SQL Injection": {
            "vuln": expect(contains=["<td>dricci</td>"]),
            "expl": expect(contains=["7en8aiDoh!", "1,admin,7en8aiDoh!"]),
        },
        "Login Bypass": {
            "vuln": expect(contains=["The username and/or password is incorrect"]),
            "expl": expect(contains=["Welcome <b>admin</b>"]),
        },
        "HTTP Parameter Pollution": {
            "vuln": expect(contains=["The username and/or password is incorrect"]),
            "expl": expect(contains=["Welcome <b>admin</b>"]),
        },
        "Cross Site Scripting (reflected)": {
            "vuln": expect(contains=["v<b>0.4</b>"]),
            "expl": expect(contains=['v<b>0.4<script>alert("arbitrary javascript")</script></b>']),
        },
        "Cross Site Scripting (stored)": {
            "vuln": expect(contains=["Comment(s)"]),
            "expl": expect(contains=["Thank you for leaving the comment"]),
        },
        "Cross Site Scripting (DOM)": {
            "vuln": expect(contains=["document.location.hash"]),
            "expl": expect(contains=["document.location.hash"]),
        },
        "Cross Site Scripting (JSONP)": {
            "vuln": expect(contains=['process({"admin": "admin"']),
            "expl": expect(contains=['alert("arbitrary javascript");process({"admin": "admin"']),
        },
        "XML External Entity (local)": {
            "vuln": expect(contains=["<root/>"], skip=None if HAS_LXML else "lxml not installed"),
            "expl": expect(contains=["root:x:0:0"] if POSIX else ["for 16-bit app support"], skip=None if HAS_LXML else "lxml not installed"),
        },
        "XML External Entity (remote)": {
            "subs": {"http%3A%2F%2Fhttpbin.org%2Fbase64%2FSGVsbG8sIFdvcmxkIQ%3D%3D": "@/xxe.txt"},
            "vuln": expect(contains=["<root/>"], skip=None if HAS_LXML else "lxml not installed"),
            "expl": expect(contains=["XXE-REMOTE-OK"], skip=None if HAS_LXML else "lxml not installed"),
        },
        "Server Side Request Forgery": {
            "subs": {"http%3A%2F%2F127.0.0.1%3A631": "@/hello.txt", "%5C%5C127.0.0.1%5CC%24%5CWindows%5Cwin.ini": "@/hello.txt"},
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(contains=["Hello, fixture!"]),
        },
        "Blind XPath Injection (boolean)": {
            "vuln": expect(contains=["<b>Surname:</b> ricci"], skip=None if HAS_LXML else "lxml not installed"),
            "expl": expect(contains=["<b>Surname:</b> admin"], skip=None if HAS_LXML else "lxml not installed"),
        },
        "Cross Site Request Forgery": {
            "vuln": expect(contains=["Comment(s)"]),
            "expl": expect(contains=['<img src="/?comment=']),
        },
        "Frame Injection (phishing)": {
            "vuln": expect(contains=["v<b>0.4</b>"]),
            "expl": expect(contains=["<iframe src=", "login.html"]),
        },
        "Frame Injection (content spoofing)": {
            "vuln": expect(contains=["v<b>0.4</b>"]),
            "expl": expect(contains=["<iframe src=", "frame.html"]),
        },
        "Clickjacking": {
            "expl": expect(contains=["opacity:0", "onclick=", "clickjacking.html"]),
        },
        "Unvalidated Redirect": {
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(code=302),                                   # 'Location' asserted separately
        },
        "Arbitrary Code Execution": {
            "subs": {"www.google.com": "localhost", "ifconfig": "echo%20ACE-MARKER", "ipconfig": "echo%20ACE-MARKER"},
            "vuln": expect(),
            "expl": expect(contains=["ACE-MARKER"]),
        },
        "Full Path Disclosure": {
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(code=500, contains=["Traceback", os.path.join(harness.ROOT, "foobar")]),
        },
        "Source Code Disclosure": {
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(contains=["#!/usr/bin/env python3", "USERS_XML", "Damn Small Vulnerable Web"]),
        },
        "Path Traversal": {
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(contains=["root:x:0:0"] if POSIX else ["for 16-bit app support"]),
        },
        "File Inclusion (remote)": {
            "subs": {"https%3A%2F%2Fpastebin.com%2Fraw%2F6VyyNNhc": "@/rfi.py", "cmd=ifconfig": "cmd=echo%20RFI-MARKER", "cmd=ipconfig": "cmd=echo%20RFI-MARKER"},
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(contains=["<pre>RFI-MARKER"]),
        },
        "HTTP Header Injection (phishing)": {
            "vuln": expect(contains=["Attacks:"]),
            "expl": expect(contains=["<title>Login</title>"]),          # raw response asserted separately
        },
        "Component with Known Vulnerability (pickle)": {
            "subs": {"ping%20-c%205%20127.0.0.1": "true", "ping%20-n%205%20127.0.0.1": "true"},
            "vuln": expect(contains=["dricci", "ricci"]),
            "expl": expect(contains=["0"]),
        },
        "Denial of Service (memory)": {
            "vuln": expect(contains=["Time required"]),
            "expl": expect(skip="would allocate gigabytes of memory on the test host"),
        },
        "Server-Side Template Injection": {
            "vuln": expect(contains=["_io.TextIOWrapper"]),
            "expl": expect(contains=["built-in function system"]),
        },
    }


def localize(url, subs):
    """Substitutes third-party targets with the local fixture ('@/path' -> url-quoted fixture url)."""
    for old, new in (subs or {}).items():
        url = url.replace(old, harness.quoted("%s%s" % (fixture_url, new[1:])) if new.startswith("@") else new)
    return url


class TestCases(unittest.TestCase):
    def test_all_cases_are_covered_by_expectations(self):
        self.assertEqual(sorted(cases()), sorted(expectations()), "dsvw.CASES and test expectations are out of sync")

    def test_cases(self):
        known, table = cases(), expectations()
        for name, (vulnerable, exploit) in known.items():
            spec = table[name]
            for kind, url in (("vulnerable", vulnerable), ("exploit", exploit)):
                rule = spec.get("vuln" if kind == "vulnerable" else "expl")
                with self.subTest(case=name, kind=kind):
                    if url is None:
                        self.assertIsNone(rule, "%s: unexpected expectation for missing '%s' url" % (name, kind))
                        continue
                    self.assertIsNotNone(rule, "%s: missing expectation for '%s'" % (name, kind))
                    if rule["skip"]:
                        self.skipTest(rule["skip"])
                    response = server.get(localize(url, spec.get("subs")), timeout=60)
                    self.assertEqual(rule["code"], response.code, "%s (%s) -> %d\n%s" % (name, kind, response.code, response.body[:2000]))
                    for marker in rule["contains"]:
                        self.assertIn(marker, response.body, "%s (%s): missing %r" % (name, kind, marker))
                    for marker in rule["absent"]:
                        self.assertNotIn(marker, response.body, "%s (%s): unexpected %r" % (name, kind, marker))
                    if rule["min_elapsed"]:
                        self.assertGreater(response.elapsed, rule["min_elapsed"], "%s (%s): response was not delayed" % (name, kind))

    def test_stored_xss_is_html_escaped_in_comment_listing(self):
        """Stored XSS: comment data read from DB must be HTML-escaped before rendering (CWE-79 fix)."""
        payload = '<script>alert("stored-xss-marker")</script>'
        server.get("/?comment=%s" % harness.quoted(payload))
        response = server.get("/?comment=")
        # The raw script tag must NOT appear verbatim in the response (would execute as JS)
        self.assertNotIn(payload, response.body)
        # Instead, the HTML-encoded form must be present (safe, browser renders as text)
        self.assertIn("&lt;script&gt;alert(&quot;stored-xss-marker&quot;)&lt;/script&gt;", response.body)

    def test_unvalidated_redirect_sends_location(self):
        response = server.get(cases()["Unvalidated Redirect"][1])
        self.assertEqual(302, response.code)
        self.assertEqual("https://geekprank.com/", response.headers.get("Location"))

    def test_header_injection_injects_real_headers(self):
        raw = server.raw_get(cases()["HTTP Header Injection (phishing)"][1])
        head = raw.split("\r\n\r\n", 1)[0]
        self.assertIn("\r\nX-XSS-Protection:0", raw)
        self.assertIn("Content-Length:388", raw)
        self.assertIn("<title>Login</title>", raw[len(head):])

    def test_attacks_index_lists_every_case(self):
        response = server.get("/")
        self.assertEqual(200, response.code)
        for name, vulnerable, exploit, info in dsvw.CASES:
            self.assertIn(name, response.body)
            self.assertIn(info, response.body)
        self.assertEqual(len(dsvw.CASES), response.body.count("info</a></li>"))

    def test_case_metadata_is_sane(self):
        names = [name for name, vulnerable, exploit, info in dsvw.CASES]
        self.assertEqual(len(names), len(set(names)), "duplicated case name")
        for name, vulnerable, exploit, info in dsvw.CASES:
            with self.subTest(case=harness.plain(name)):
                self.assertRegex(info, r"^https?://")
                self.assertTrue(exploit.startswith('/'), "exploit url has to be absolute: %r" % exploit)
                self.assertTrue(vulnerable is None or vulnerable.startswith(('/', '?')), "unexpected vulnerable url: %r" % vulnerable)
                self.assertNotIn(" ", html.unescape(exploit.split('"')[0]), "unencoded space in exploit url")

    def test_index_disables_nothing_when_lxml_is_available(self):
        if not HAS_LXML:
            self.skipTest("lxml not installed")
        self.assertNotIn("class=\"disabled\"", server.get("/").body)

    def test_index_disables_xml_cases_without_lxml(self):
        if HAS_LXML:
            self.skipTest("lxml is installed")
        body = server.get("/").body
        expected = [name for name, vulnerable, exploit, info in dsvw.CASES if any(_ in name.upper() for _ in ("XML", "XPATH"))]
        self.assertEqual(len(expected), body.count("class=\"disabled\""))
        self.assertIn("module 'python-lxml' not installed", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
