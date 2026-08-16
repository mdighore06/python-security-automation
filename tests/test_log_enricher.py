from log_enricher import is_public_ip, extract_public_ips

def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("192.168.1.1") is False

def test_extract_public_ips(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("Failed login from 8.8.8.8 and 10.0.0.1")
    ips = extract_public_ips(str(log_file))
    assert "8.8.8.8" in ips
    assert "10.0.0.1" not in ips
