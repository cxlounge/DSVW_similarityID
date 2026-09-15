#!/usr/bin/env python3

"""Test harness: runs 'dsvw.py' as a real subprocess and talks HTTP to it."""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DSVW = os.path.join(ROOT, "dsvw.py")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Response:
    def __init__(self, code, body, headers, elapsed):
        self.code, self.body, self.headers, self.elapsed = code, body, headers, elapsed

    def __contains__(self, item):
        return item in self.body


def get(url, timeout=30, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    start = time.time()
    try:
        response = OPENER.open(request, timeout=timeout)
        return Response(response.status, response.read().decode("utf8", "replace"), response.headers, time.time() - start)
    except urllib.error.HTTPError as ex:
        return Response(ex.code, ex.read().decode("utf8", "replace"), ex.headers, time.time() - start)


def raw_request(address, port, method, selector, body=None, content_length=None, extra=(), timeout=15):
    lines = ["%s %s HTTP/1.0" % (method, selector), "Host: %s:%d" % (address, port), "Connection: close"]
    if body is not None:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append("Content-Length: %s" % (len(body) if content_length is None else content_length))
    lines.extend(extra)
    with socket.create_connection((address, port), timeout=timeout) as sock:
        sock.sendall(("%s\r\n\r\n" % "\r\n".join(lines)).encode() + (body if isinstance(body, bytes) else (body or "").encode()))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf8", "replace")


def raw_get(address, port, selector, **kwargs):
    return raw_request(address, port, "GET", selector, **kwargs)


def split_response(raw):
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    return lines[0], dict((key.strip().lower(), value.strip()) for key, _, value in (line.partition(':') for line in lines[1:])), body


class Dsvw:
    """Lifecycle wrapper around a 'dsvw.py' subprocess."""

    def __init__(self, *args, port=None, wait=True, executable=None):
        self.port = port if port is not None else free_port()
        self.address = "127.0.0.1"
        self.log = tempfile.NamedTemporaryFile(mode="w+", prefix="dsvw-log-", suffix=".txt", delete=False)
        argv = [executable or sys.executable, "-u", DSVW]
        argv.extend(args if args else ["--port=%d" % self.port])
        self.process = subprocess.Popen(argv, cwd=ROOT, stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.started = wait and self.wait_ready()

    @property
    def base(self):
        return "http://%s:%d" % (self.address, self.port)

    def url(self, path):
        return "%s%s" % (self.base, path if path.startswith('/') else "/%s" % path)

    def get(self, path, **kwargs):
        return get(self.url(path), **kwargs)

    def raw_get(self, selector, **kwargs):
        return raw_get(self.address, self.port, selector, **kwargs)

    def raw_request(self, method, selector, **kwargs):
        return raw_request(self.address, self.port, method, selector, **kwargs)

    def wait_ready(self, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                with socket.create_connection((self.address, self.port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    def output(self):
        with open(self.log.name, "r", errors="replace") as handle:
            return handle.read()

    def wait(self, timeout=15):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        return self.process.returncode

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()

    def cleanup(self):
        self.stop()
        try:
            os.unlink(self.log.name)
        except OSError:
            pass


def interpreters(minimum=(3, 7)):
    """Every usable python3.x interpreter on the box (missing pyenv shims and incomplete builds are skipped)."""
    probe = "import sys, html, http.client, http.server, io, json, os, random, re, socket, socketserver, sqlite3, string, subprocess, time, traceback, urllib.parse, urllib.request, xml.etree.ElementTree; sys.exit(0 if sys.version_info[:2] >= %r else 1)" % (minimum,)
    result = []
    for minor in range(minimum[1], 14):
        path = shutil.which("python3.%d" % minor)
        if path and subprocess.run([path, "-c", probe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            result.append(path)
    return result


def plain(text):
    return re.sub(r"<[^>]+>", "", text or "")


def quoted(url):
    return urllib.parse.quote(url, safe="")
