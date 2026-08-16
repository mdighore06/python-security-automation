from virustotal_check import query_virustotal

def test_virustotal_missing_api_key():
    res = query_virustotal("8.8.8.8", "")
    assert "error" in res
