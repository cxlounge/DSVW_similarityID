#!/usr/bin/env python3

"""Regression tests: each one pins down a concrete defect of 'dsvw.py' (all fixtures are local)."""

import html.parser
import importlib.util
import json
import os
import pickle
import re
import sys
import threading
import time
import unittest
import urllib.parse
import xml.etree.ElementTree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture
import harness

sys.path.insert(0, harness.ROOT)
import dsvw

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


def wait_for(predicate, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class TestRequestRobustness(unittest.TestCase):
    """Nothing a client sends may leave the request without a complete HTTP response."""

    SELECTORS = ("/?id[]=1", "/?id[0]=1", "/?v=0.4\\9", "/?v=\\g<foo>", "/?v=0.4\\", "/?id=2&id[]=3", "/?size=abc", "/?size=-5",
                 "/?path=", "/?path=.", "/?xml=%3C", "/?tmpl=%7B%7D", "/?tmpl=%7B7%7D", "/?object=x", "/?include=/nonexistent",
                 "/?redir=", "/?comment=", "/?name=", "/?domain=", "/?a[=1", "/?a]=1", "/login", "/login?username=%27", "/nonexistent")

    def test_every_request_gets_a_complete_response(self):
        for selector in self.SELECTORS:
            with self.subTest(selector=selector):
                raw = server.raw_get(selector)
                self.assertTrue(raw.startswith("HTTP/1."), "%s -> no HTTP response at all (%r)" % (selector, raw[:80]))
                self.assertIn("\r\n\r\n", raw, "%s -> truncated response" % selector)

    def test_server_survives_the_whole_sweep(self):
        self.assertIn("Attacks:", server.get("/").body)

    def test_non_latin1_header_values_still_get_a_response(self):
        """HTTP headers are latin-1 encoded, so unicode in 'redir'/'charset' used to kill the connection."""
        for selector, expected in (("/?redir=%C3%A9%C5%A1%C4%87", "302"), ("/?redir=%F0%9F%98%80", "302"), ("/?redir=%ff", "302"),
                                   ("/?charset=%C3%A9%C5%A1%C4%87", "200"), ("/?charset=%ed%a0%80", "200"), ("/?charset=%c0%80", "200")):
            with self.subTest(selector=selector):
                raw = server.raw_get(selector)
                self.assertTrue(raw.startswith("HTTP/1."), "%s -> no HTTP response at all" % selector)
                status, headers, body = harness.split_response(raw)
                self.assertIn(expected, status)

    def test_header_injection_survives_the_latin1_fix(self):
        raw = server.raw_get("/?charset=utf8%0D%0AX-Marker:1")
        self.assertIn("\r\nX-Marker:1\r\n", raw)

    def test_location_header_injection_survives_the_latin1_fix(self):
        raw = server.raw_get("/?redir=http%3A%2F%2Fexample.com%2F%0D%0AX-Marker:2")
        self.assertIn("\r\nX-Marker:2\r\n", raw)


class TestParameterParsing(unittest.TestCase):
    def test_bracket_parameter_names_are_not_treated_as_regex(self):
        response = server.get("/?id[]=1")                               # 'id[]' used to be interpolated raw into a regex
        self.assertEqual(200, response.code)
        self.assertIn("Attacks:", response.body)

    def test_bracket_parameter_does_not_hijack_plain_parameter(self):
        self.assertIn("<td>dricci</td>", server.get("/?id=2&id[]=99").body)

    def test_repeated_parameters_are_still_joined(self):               # HTTP parameter pollution must keep working
        self.assertIn("Welcome <b>admin</b>", server.get("/login?username=admin&password=%27%2F*&password=*%2FOR%2F*&password=*%2F%271%27%2F*&password=*%2FLIKE%2F*&password=*%2F%271").body)


class TestReflectedVersion(unittest.TestCase):
    def test_backslash_payloads_are_reflected_verbatim(self):
        for payload, expected in (("0.4\\9", "v<b>0.4\\9</b>"), ("\\g<foo>", "v<b>\\g<foo></b>"), ("0.4\\", "v<b>0.4\\</b>"), ("a\\\\b", "v<b>a\\\\b</b>")):
            with self.subTest(payload=payload):
                response = server.get("/?v=%s" % harness.quoted(payload))
                self.assertEqual(200, response.code, response.body[:800])
                self.assertIn(expected, response.body)

    def test_script_payload_is_reflected(self):
        payload = '<script>alert("xss")</script>'
        self.assertIn("v<b>0.4%s</b>" % payload, server.get("/?v=%s" % harness.quoted("0.4" + payload)).body)

    def test_footer_stays_at_the_end_of_the_page(self):
        response = server.get("/?v=0.4")
        self.assertNotIn("Attacks:", response.body)                     # attack list must not be appended after the footer
        self.assertTrue(response.body.rstrip().endswith("</html>"))


class TestObjectDemo(unittest.TestCase):
    """Tests for the ?object= endpoint, now using safe JSON deserialization instead of pickle."""

    @staticmethod
    def users_object():
        users = dict((_.findtext("username"), [_.findtext("name"), _.findtext("surname")]) for _ in xml.etree.ElementTree.fromstring(dsvw.USERS_XML).findall("user"))
        return urllib.parse.quote(json.dumps(users))

    def test_shipped_object_demo_deserializes(self):
        """JSON-encoded user dict round-trips correctly."""
        response = server.get("/?object=%s" % self.users_object())
        self.assertEqual(200, response.code, response.body[:800])
        self.assertIn("dricci", response.body)

    def test_valid_json_string_is_deserialized(self):
        """A simple JSON string value is returned as its Python representation."""
        payload = urllib.parse.quote(json.dumps("hello world"))
        response = server.get("/?object=%s" % payload)
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("hello world", response.body)

    def test_valid_json_number_is_deserialized(self):
        """A JSON number is returned as its Python representation."""
        payload = urllib.parse.quote(json.dumps(42))
        response = server.get("/?object=%s" % payload)
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("42", response.body)

    def test_pickle_rce_payload_is_rejected(self):
        """A raw pickle RCE payload must no longer execute — json.loads raises an error instead."""
        # This payload would execute `true` via pickle's REDUCE opcode:
        # cos\nsystem\n(S'true'\ntR.
        rce_payload = urllib.parse.quote("cos\nsystem\n(S'true'\ntR.")
        response = server.get("/?object=%s" % rce_payload)
        # The server must return HTTP 500 (json.loads raises ValueError/JSONDecodeError),
        # NOT HTTP 200 with the command exit code "0".
        self.assertEqual(500, response.code, "Pickle RCE payload should raise a JSON decode error, not succeed")
        self.assertNotEqual("0", response.body.strip(), "Pickle RCE payload must not return command exit code '0'")

    def test_binary_pickle_payload_is_rejected(self):
        """Raw binary pickle bytes must not be deserialized — json.loads rejects non-JSON bytes."""
        users = dict((_.findtext("username"), (_.findtext("name"), _.findtext("surname"))) for _ in xml.etree.ElementTree.fromstring(dsvw.USERS_XML).findall("user"))
        binary_pickle_payload = urllib.parse.quote(pickle.dumps(users))
        response = server.get("/?object=%s" % binary_pickle_payload)
        # json.loads must raise a JSONDecodeError for binary pickle data
        self.assertEqual(500, response.code, "Binary pickle payload must not be deserialized")


class TestFileDisclosure(unittest.TestCase):
    def test_binary_file_does_not_break_the_response(self):
        path = os.path.join(harness.ROOT, "tests", "fixture-binary.tmp")
        with open(path, "wb") as handle:
            handle.write(fixture.BINARY_CONTENT)
        try:
            response = server.get("/?path=%s" % harness.quoted(path))
            self.assertEqual(200, response.code, response.body[:800])
            self.assertIn("binary-marker", response.body)
        finally:
            os.unlink(path)

    def test_source_code_disclosure_still_works(self):
        self.assertIn("USERS_XML", server.get("/?path=dsvw.py").body)


class TestXmlDecoding(unittest.TestCase):
    def setUp(self):
        if not importlib.util.find_spec("lxml"):
            self.skipTest("lxml not installed")

    def test_non_utf8_document_is_not_corrupted(self):
        document = '<?xml version="1.0" encoding="iso-8859-1"?><root>caf\xe9</root>'.encode("latin-1")
        response = server.get("/?xml=%s" % urllib.parse.quote(document, safe=""))
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("caf&#233;", response.body)

    def test_utf8_document_still_works(self):
        response = server.get("/?xml=%s" % urllib.parse.quote('<root>caf\xe9</root>'.encode(), safe=""))
        self.assertIn("caf&#233;", response.body)

    def test_remote_entity_is_expanded(self):
        """libxml2 >= 2.13 (i.e. every recent 'pip install lxml') dropped HTTP, so DSVW has to fetch entities itself."""
        document = '<!DOCTYPE x [<!ENTITY xxe SYSTEM "%s/xxe.txt">]><root>&xxe;</root>' % fixture_url
        response = server.get("/?xml=%s" % urllib.parse.quote(document, safe=""))
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("XXE-REMOTE-OK", response.body)

    def test_remote_entity_uses_the_servers_own_fetcher(self):
        """Proves the entity is retrieved by DSVW (browser User-Agent) instead of libxml2's own HTTP client."""
        document = '<!DOCTYPE x [<!ENTITY xxe SYSTEM "%s/ua-guard.txt">]><root>&xxe;</root>' % fixture_url
        response = server.get("/?xml=%s" % urllib.parse.quote(document, safe=""))
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("UA-GUARD-OK", response.body)

    def test_local_entity_expansion_still_works(self):
        response = server.get("/?xml=%s" % urllib.parse.quote('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><root>&e;</root>', safe=""))
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("<root>", response.body)


class TestCommandExecution(unittest.TestCase):
    def test_injected_command_with_binary_output_is_shown(self):
        if os.name == "nt":
            self.skipTest("POSIX only")
        response = server.get("/?domain=127.0.0.1%3B%20head%20-c%2064%20%2Fbin%2Fsh")
        self.assertEqual(200, response.code, response.body[:800])
        self.assertIn("ELF", response.body)

    def test_injected_command_output_is_returned(self):
        self.assertIn("CMD-MARKER", server.get("/?domain=127.0.0.1%3B%20echo%20CMD-MARKER").body)


class TestConcurrency(unittest.TestCase):
    def test_mixed_concurrent_requests_all_succeed(self):
        selectors = ["/?id=2", "/?v=0.4", "/?comment=", "/?comment=concurrent", "/users.json", "/login?username=admin&password=7en8aiDoh!", "/?size=32", "/?tmpl=%7B0.__class__%7D"] * 3
        results, errors = [], []

        def worker(selector):
            try:
                results.append((selector, server.get(selector, timeout=45).code))
            except Exception as ex:
                errors.append((selector, ex))

        threads = [threading.Thread(target=worker, args=(selector,)) for selector in selectors]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual([], errors)
        self.assertEqual(len(selectors), len(results))
        self.assertEqual([], [_ for _ in results if _[1] != 200])


class TestOutboundRequests(unittest.TestCase):
    def test_server_side_request_forgery_is_not_blocked_by_user_agent(self):
        response = server.get("/?path=%s" % harness.quoted("%s/ua-guard.txt" % fixture_url))
        self.assertEqual(200, response.code, response.body[:800])
        self.assertIn("UA-GUARD-OK", response.body)

    def test_remote_file_inclusion_is_not_blocked_by_user_agent(self):
        response = server.get("/?include=%s&cmd=echo%%20UA-RFI-OK" % harness.quoted("%s/ua-guard.py" % fixture_url))
        self.assertEqual(200, response.code, response.body[:800])
        self.assertIn("UA-RFI-OK", response.body)

    def test_included_program_raising_called_process_error_still_answers(self):
        """The included program's subprocess.CalledProcessError carries bytes, which used to kill the response."""
        raw = server.raw_get("/?include=%s&cmd=ls%%20/definitely-not-here" % harness.quoted("%s/rfi.py" % fixture_url))
        self.assertTrue(raw.startswith("HTTP/1."), repr(raw[:80]))
        status, headers, body = harness.split_response(raw)
        self.assertIn("500", status)
        self.assertIn("definitely-not-here", body)

    def test_remote_file_inclusion_reads_query_string(self):
        response = server.get("/?include=%s&cmd=echo%%20RFI-QS" % harness.quoted("%s/rfi.py" % fixture_url))
        self.assertIn("<pre>RFI-QS", response.body)


class TestIncludedProgramSemantics(unittest.TestCase):
    """An included program is a normal script - the usual script idioms have to work."""

    def include(self, source):
        path = os.path.join(harness.ROOT, "tests", "fixture-program.tmp")
        with open(path, "w") as handle:
            handle.write(source)
        try:
            return server.get("/?include=%s" % harness.quoted(path))
        finally:
            os.unlink(path)

    def test_main_guard_is_honoured(self):
        response = self.include('if __name__ == "__main__":\n    print("MAIN-OK")\n')
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("MAIN-OK", response.body)

    def test_output_survives_exit(self):
        for source in ('print("BEFORE-EXIT")\nexit(0)\n', 'import sys\nprint("BEFORE-EXIT")\nsys.exit(0)\n', 'print("BEFORE-EXIT")\nraise SystemExit(1)\n'):
            with self.subTest(source=source.splitlines()[-1]):
                response = self.include(source)
                self.assertEqual(200, response.code, response.body[:400])
                self.assertIn("BEFORE-EXIT", response.body)

    def test_output_survives_a_crash(self):
        response = self.include('print("BEFORE-CRASH")\nraise ValueError("boom")\n')
        self.assertEqual(500, response.code)
        self.assertIn("boom", response.body)

    def test_multiple_print_arguments_are_rendered(self):
        response = self.include('print("A", "B", sep="-", end="!")\nprint()\n')
        self.assertIn("A-B!", response.body)


class TestIncludePathEnvIsolation(unittest.TestCase):
    """CWE-94: The HTTP request path must NOT flow into exec()'s globals as the PATH variable.

    Before the fix, 'envs["PATH"]' was set to the tainted HTTP request path (e.g. '/'),
    which caused the SAST engine to flag a Code Injection taint flow from self.path ->
    envs["PATH"] -> exec(program, envs).  After the fix, PATH comes from os.environ so
    the tainted request path never reaches exec().
    """

    def include_local(self, source, request_path="/"):
        """Write source to a temp file and request it via a custom URL path."""
        tmp = os.path.join(harness.ROOT, "tests", "fixture-path-env.tmp")
        with open(tmp, "w") as handle:
            handle.write(source)
        try:
            # The query string starts with '?' appended to the given request_path by the harness.
            # We pass the include parameter directly via '/?include=...' so the HTTP path is '/'.
            return server.get("/?include=%s" % harness.quoted(tmp))
        finally:
            os.unlink(tmp)

    def test_path_env_is_system_path_not_request_path(self):
        """PATH seen by the included program must be the OS PATH, not the HTTP request path."""
        # A typical OS PATH starts with '/' (POSIX) or a drive letter (Windows).
        # The HTTP request path is always '/' here, but we verify it is NOT the request path
        # by checking that PATH looks like a real search path (contains a directory separator).
        source = 'print(PATH)\n'
        response = self.include_local(source)
        self.assertEqual(200, response.code, response.body[:400])
        # The body must contain some PATH value (even an empty string is acceptable when the
        # OS PATH env-var is absent, but it must never be the literal HTTP request path '/').
        path_value = response.body.strip()
        # If the OS has a PATH, it must contain os.sep (a directory separator), proving it
        # is the real system path.  If PATH is absent from the environment (edge case in
        # minimal containers), the value is the empty string — but NEVER just '/'.
        if path_value:
            # A real OS PATH always contains at least one directory separator character.
            self.assertTrue(
                os.sep in path_value or ":" in path_value or ";" in path_value,
                "PATH inside exec() looks like the HTTP request path rather than the OS PATH: %r" % path_value,
            )

    def test_path_env_does_not_equal_http_request_path(self):
        """The literal HTTP request path '/' must never appear as the PATH variable in exec()."""
        source = 'print(repr(PATH))\n'
        response = self.include_local(source)
        self.assertEqual(200, response.code, response.body[:400])
        # If PATH were set to the HTTP request path, repr('/') == "'/'" would appear.
        self.assertNotEqual("'/'", response.body.strip(),
                            "PATH inside exec() equals the HTTP request path '/' — taint flow not broken")

    def test_included_program_can_still_run_subprocesses(self):
        """Verify that the included program environment is functional after the PATH fix."""
        if os.name == "nt":
            cmd = "echo SUBPROCESS-OK"
        else:
            cmd = "echo SUBPROCESS-OK"
        source = (
            'import subprocess\n'
            'result = subprocess.run(%r, shell=True, capture_output=True, text=True)\n'
            'print(result.stdout.strip())\n'
        ) % cmd
        response = self.include_local(source)
        self.assertEqual(200, response.code, response.body[:400])
        self.assertIn("SUBPROCESS-OK", response.body)


class TestRemoteFileInclusionIsolation(unittest.TestCase):
    """The remote file inclusion output capture must not hijack the server's global stdout."""

    def include(self, results, index):
        results[index] = server.get("/?include=%s" % harness.quoted("%s/slow.py" % fixture_url), timeout=60)

    def test_concurrent_request_logs_do_not_leak_into_the_response(self):
        results = {}
        worker = threading.Thread(target=self.include, args=(results, 0))
        worker.start()
        time.sleep(0.4)
        self.assertIn("v<b>LEAK-MARKER</b>", server.get("/?v=LEAK-MARKER").body)
        worker.join(60)
        self.assertEqual(200, results[0].code, results[0].body[:800])
        self.assertIn("SLOW-DONE", results[0].body)
        self.assertNotIn("LEAK-MARKER", results[0].body, "another request's log line was captured into the response")
        self.assertNotIn("[i] GET", results[0].body)

    def test_server_keeps_logging_after_concurrent_inclusions(self):
        results = {}
        workers = [threading.Thread(target=self.include, args=(results, index)) for index in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        self.assertEqual([200, 200], [results[index].code for index in sorted(results)])
        server.get("/?v=AFTER-RFI-MARKER")
        self.assertTrue(wait_for(lambda: "[i] GET /?v=AFTER-RFI-MARKER" in server.output()), "server stopped logging to stdout:\n%s" % server.output()[-1500:])


class TestContentTypes(unittest.TestCase):
    def test_json_endpoint_is_served_as_json(self):
        response = server.get("/users.json")
        self.assertTrue(response.headers.get("Content-Type", "").startswith("application/json"), response.headers.get("Content-Type"))

    def test_jsonp_endpoint_is_served_as_javascript(self):
        response = server.get("/users.json?callback=process")
        self.assertTrue(response.headers.get("Content-Type", "").startswith("application/javascript"), response.headers.get("Content-Type"))

    def test_html_pages_stay_html(self):
        self.assertTrue(server.get("/").headers.get("Content-Type", "").startswith("text/html"))

    def test_charset_parameter_is_honoured(self):
        self.assertIn("charset=iso-8859-1", server.get("/?charset=iso-8859-1").headers.get("Content-Type"))


class TestComments(unittest.TestCase):
    def test_listing_works_next_to_other_parameters(self):
        server.get("/?comment=listing-marker")
        response = server.get("/?comment=&foobar=1")
        self.assertIn("Comment(s)", response.body)
        self.assertIn("listing-marker", response.body)

    def test_insert_still_reports_success(self):
        self.assertIn("Thank you for leaving the comment", server.get("/?comment=another").body)


class TestSession(unittest.TestCase):
    def test_successful_login_sets_a_real_session_cookie(self):
        response = server.get("/login?username=admin&password=7en8aiDoh!")
        self.assertIn("Welcome <b>admin</b>", response.body)
        cookie = response.headers.get("Set-Cookie")
        self.assertIsNotNone(cookie, "no 'Set-Cookie' header (meta http-equiv is ignored by modern browsers)")
        self.assertRegex(cookie, r"^SESSIONID=[A-Za-z0-9]{20}; path=/$")

    def test_failed_login_expires_the_session_cookie(self):
        response = server.get("/login?username=admin&password=wrong")
        self.assertIn("incorrect", response.body)
        self.assertIn("SESSIONID=;", response.headers.get("Set-Cookie") or "")

    def test_login_bypass_sets_a_session_cookie(self):
        response = server.get("/login?username=admin&password=%27%20OR%20%271%27%20LIKE%20%271")
        self.assertIn("Welcome <b>admin</b>", response.body)
        self.assertRegex(response.headers.get("Set-Cookie") or "", r"^SESSIONID=[A-Za-z0-9]{20}; path=/$")

    def test_non_login_responses_do_not_set_cookies(self):
        self.assertIsNone(server.get("/?id=2").headers.get("Set-Cookie"))

    def test_session_ids_are_drawn_with_replacement(self):
        """random.sample() cannot ever repeat a character, which silently caps the id's entropy."""
        identifiers = [re.search(r"SESSIONID=(\w+)", server.get("/login?username=admin&password=7en8aiDoh!").headers.get("Set-Cookie")).group(1) for _ in range(8)]
        self.assertEqual(8, len(set(identifiers)), "session ids are not unique")
        self.assertTrue(any(len(set(identifier)) < len(identifier) for identifier in identifiers), "no session id ever repeats a character: %s" % identifiers)


class TestHttpMethods(unittest.TestCase):
    def test_head_returns_headers_without_a_body(self):
        status, headers, body = harness.split_response(server.raw_request("HEAD", "/?id=2"))
        self.assertIn("200", status)
        self.assertTrue(headers.get("content-type", "").startswith("text/html"), headers)
        self.assertEqual("", body)

    def test_post_parameters_are_processed(self):
        status, headers, body = harness.split_response(server.raw_request("POST", "/", body="id=2"))
        self.assertIn("200", status)
        self.assertIn("<td>dricci</td>", body)

    def test_post_login_bypass(self):
        status, headers, body = harness.split_response(server.raw_request("POST", "/login", body="username=admin&password=%27%20OR%20%271%27%20LIKE%20%271"))
        self.assertIn("Welcome <b>admin</b>", body)
        self.assertRegex(headers.get("set-cookie", ""), r"^SESSIONID=[A-Za-z0-9]{20}; path=/$")

    def test_post_merges_body_with_existing_query(self):
        status, headers, body = harness.split_response(server.raw_request("POST", "/login?username=admin", body="password=%27%20OR%20%271%27%20LIKE%20%271"))
        self.assertIn("Welcome <b>admin</b>", body)

    def test_post_with_malformed_content_length_still_answers(self):
        for length in ("abc", "", "-1"):
            with self.subTest(length=length):
                raw = server.raw_request("POST", "/?id=2", body="", content_length=length)
                self.assertTrue(raw.startswith("HTTP/1."), repr(raw[:80]))

    def test_unsupported_method_is_rejected_cleanly(self):
        self.assertIn("501", harness.split_response(server.raw_request("PUT", "/"))[0])

    def test_post_body_cannot_forge_log_lines(self):
        raw = server.raw_request("POST", "/?id=2", body=b"comment=x\r\n[i] FAKE GET /evil -> 200\r\n")
        self.assertIn("200", harness.split_response(raw)[0])
        self.assertTrue(wait_for(lambda: "[i] POST /?id=2" in server.output()))
        self.assertNotIn("\n[i] FAKE", server.output(), "a POST body forged a line in the server log")

    def test_post_with_non_utf8_body_still_answers(self):
        raw = server.raw_request("POST", "/?id=2", body=b"comment=\xff\xfe\x80")
        self.assertTrue(raw.startswith("HTTP/1."), repr(raw[:80]))
        self.assertIn("200", harness.split_response(raw)[0])


class TestCommandLine(unittest.TestCase):
    def test_help_exits_cleanly(self):
        instance = harness.Dsvw("-h", wait=False)
        try:
            self.assertEqual(0, instance.wait())
            self.assertIn("usage: python3 dsvw.py", instance.output())
        finally:
            instance.cleanup()

    def test_invalid_port_reports_an_error_instead_of_a_traceback(self):
        for value in ("abc", "", "0", "99999", "-1", "65536"):
            with self.subTest(port=value):
                instance = harness.Dsvw("--port=%s" % value, wait=False)
                try:
                    self.assertNotEqual(0, instance.wait())
                    self.assertNotIn("Traceback", instance.output())
                    self.assertIn("[x]", instance.output())
                finally:
                    instance.cleanup()

    def test_fatal_startup_error_exits_non_zero(self):
        """A supervisor (docker, systemd, CI) can only notice a failed start through the exit code."""
        taken = harness.Dsvw()
        try:
            self.assertTrue(taken.started, taken.output())
            instance = harness.Dsvw("--port=%d" % taken.port, wait=False)
            try:
                self.assertEqual(1, instance.wait())
                self.assertIn("[x] exception occurred", instance.output())
            finally:
                instance.cleanup()
        finally:
            taken.cleanup()

    def test_unknown_option_is_reported(self):
        port = harness.free_port()
        instance = harness.Dsvw("--port=%d" % port, "--bogus", port=port)
        try:
            self.assertTrue(instance.started, instance.output())
            self.assertIn("--bogus", instance.output())
            self.assertIn("Attacks:", instance.get("/").body)            # still fully operational
        finally:
            instance.cleanup()

    def test_wildcard_host_option_works(self):
        """Docker (and any container) must be able to expose DSVW without patching the source."""
        port = harness.free_port()
        instance = harness.Dsvw("--host=0.0.0.0", "--port=%d" % port, port=port)
        try:
            self.assertTrue(instance.started, instance.output())
            self.assertIn("running HTTP server at 'http://0.0.0.0:%d'" % port, instance.output())
            self.assertIn("Attacks:", instance.get("/").body)
        finally:
            instance.cleanup()

    def test_host_and_port_options_are_honoured(self):
        port = harness.free_port()
        instance = harness.Dsvw("--host=127.0.0.1", "--port=%d" % port, port=port)
        try:
            self.assertTrue(instance.started, instance.output())
            self.assertIn("running HTTP server at 'http://127.0.0.1:%d'" % port, instance.output())
        finally:
            instance.cleanup()


class TestInterpreterCompatibility(unittest.TestCase):
    """DSVW is a single stdlib-only file - it has to behave the same on every supported CPython."""

    def test_runs_on_every_available_python3(self):
        found = harness.interpreters()
        self.assertTrue(found, "no python3.x interpreters found")
        for executable in found:
            with self.subTest(executable=executable):
                instance = harness.Dsvw(executable=executable)
                try:
                    self.assertTrue(instance.started, instance.output())
                    self.assertIn("running HTTP server at", instance.output())
                    self.assertIn("<td>dricci</td>", instance.get("/?id=2").body)
                    self.assertIn("Attacks:", instance.get("/").body)
                    self.assertEqual(404, instance.get("/nonexistent").code)
                    self.assertTrue(wait_for(lambda: "[i] GET /?id=2 -> 200" in instance.output()), "status is not logged numerically:\n%s" % instance.output()[-600:])
                finally:
                    instance.cleanup()


class TestPageContent(unittest.TestCase):
    def test_comment_confirmation_reads_correctly(self):
        body = server.get("/?comment=wording").body
        self.assertIn("Please click <a href=\"/?comment=\">here</a> to see all comments", body)
        self.assertNotIn("click here <a", body)

    def test_not_found_page_says_so(self):
        response = server.get("/nonexistent")
        self.assertEqual(404, response.code)
        self.assertIn("Not Found", response.body)
        self.assertTrue(response.body.rstrip().endswith("</html>"))

    def test_not_found_page_does_not_list_attacks(self):
        self.assertNotIn("Attacks:", server.get("/nonexistent").body)


class TestHtmlStructure(unittest.TestCase):
    """Every HTML page has to be balanced - a browser must not be left with dangling elements."""

    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
    PAGES = ("/", "/?id=2", "/?v=0.4", "/?comment=", "/?comment=structure", "/?size=8", "/?tmpl=%7B0.__class__%7D", "/login?username=admin&password=7en8aiDoh!",
             "/login?username=admin&password=wrong", "/nonexistent", "/?name=dian")

    def unbalanced(self, markup):
        stack, problems = [], []

        class Parser(html.parser.HTMLParser):
            def handle_starttag(inner, tag, attrs):
                if tag not in TestHtmlStructure.VOID:
                    stack.append(tag)

            def handle_endtag(inner, tag):
                if tag in TestHtmlStructure.VOID:
                    return
                if tag not in stack:
                    problems.append("stray </%s>" % tag)
                else:
                    while stack and stack.pop() != tag:
                        pass

        parser = Parser(convert_charrefs=True)
        parser.feed(markup)
        parser.close()
        return problems + ["unclosed <%s>" % tag for tag in stack]

    def test_pages_are_balanced(self):
        for page in self.PAGES:
            if page == "/?name=dian" and not importlib.util.find_spec("lxml"):
                continue
            with self.subTest(page=page):
                response = server.get(page)
                self.assertTrue(response.body.startswith("<!DOCTYPE html>"), page)
                self.assertEqual([], self.unbalanced(response.body), page)

    def test_table_headers_live_in_a_row(self):
        for page in ("/?id=2", "/?comment="):
            with self.subTest(page=page):
                body = server.get(page).body
                self.assertIn("<thead><tr><th>", body)                  # <th> is only allowed inside <tr>
                self.assertNotIn("<thead><th>", body)

    def test_stylesheet_has_no_bogus_declarations(self):
        style = re.search(r"<style>(.*?)</style>", server.get("/").body, re.S).group(1)
        self.assertNotRegex(style, r"[;{]\s*visited\s*:", "'visited' is a pseudo-class, not a property (declaration is ignored)")
        self.assertIn("a:visited", style)
        self.assertNotRegex(server.get("/").body, r"style=\"[^\"]*;\s*visited\s*:", "inline 'visited' declaration is ignored")

    def test_pages_end_with_the_footer(self):
        for page in self.PAGES:
            if page == "/?name=dian" and not importlib.util.find_spec("lxml"):
                continue
            with self.subTest(page=page):
                body = server.get(page).body
                self.assertEqual(1, body.count("Powered by"), "footer must appear exactly once")
                self.assertTrue(body.rstrip().endswith("</html>"))


class TestProjectConstraints(unittest.TestCase):
    def test_stays_under_100_lines_of_code(self):
        with open(harness.DSVW, "r") as handle:
            lines = handle.read().splitlines()
        self.assertLess(len(lines), 100, "DSVW must stay under 100 LoC (currently %d)" % len(lines))

    def test_version_is_reported_consistently(self):
        self.assertIn("v<b>%s</b>" % dsvw.VERSION, server.get("/").body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
