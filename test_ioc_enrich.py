from ioc_enrich import refang, detect_type, parse_input, classify, markdown_report


def test_refang():
    assert refang("bad[.]com") == "bad.com"
    assert refang("hxxp://bad[.]com/x") == "http://bad.com/x"
    assert refang("hxxps://bad[dot]com") == "https://bad.com"
    assert refang("  8.8.8.8 ") == "8.8.8.8"


def test_detect_ip():
    assert detect_type("8.8.8.8") == ("8.8.8.8", "ip")
    assert detect_type("999.1.1.1") == ("999.1.1.1", None)


def test_detect_hash():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert detect_type(md5) == (md5, "hash")
    assert detect_type(sha256.upper()) == (sha256, "hash")


def test_detect_domain():
    assert detect_type("Evil-Site.com") == ("evil-site.com", "domain")
    assert detect_type("bad[.]com") == ("bad.com", "domain")
    assert detect_type("not a domain") == ("not a domain", None)


def test_detect_url_reduces_to_host():
    assert detect_type("hxxp://bad[.]com:8080/payload.exe") == ("bad.com", "domain")
    assert detect_type("https://1.2.3.4/login") == ("1.2.3.4", "ip")


def test_parse_input_dedupes_and_skips():
    lines = ["8.8.8.8", "", "# comment", "8.8.8.8", "garbage!!!", "bad[.]com"]
    iocs, skipped = parse_input(lines)
    assert [i["ioc"] for i in iocs] == ["8.8.8.8", "bad.com"]
    assert skipped == ["garbage!!!"]


def test_classify_malicious():
    assert classify({"found": True, "malicious": 5, "suspicious": 0}, None) == "malicious"
    assert classify(None, {"score": 90}) == "malicious"


def test_classify_suspicious():
    assert classify({"found": True, "malicious": 1, "suspicious": 0}, None) == "suspicious"
    assert classify({"found": True, "malicious": 0, "suspicious": 2}, None) == "suspicious"
    assert classify(None, {"score": 30}) == "suspicious"


def test_classify_clean_and_unknown():
    assert classify({"found": True, "malicious": 0, "suspicious": 0}, None) == "clean"
    assert classify(None, {"score": 0}) == "clean"
    assert classify(None, None) == "unknown"
    assert classify({"found": False}, None) == "unknown"


def test_markdown_report_sorts_by_severity():
    results = [
        {"ioc": "good.com", "type": "domain", "verdict": "clean", "vt": {"found": True, "malicious": 0, "suspicious": 0}, "abuse": None, "notes": ""},
        {"ioc": "1.2.3.4", "type": "ip", "verdict": "malicious", "vt": None, "abuse": {"score": 100, "reports": 50}, "notes": ""},
    ]
    report = markdown_report(results, [])
    assert report.index("1.2.3.4") < report.index("good.com")
    assert "2 IOCs checked" in report
