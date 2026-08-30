from release_sentinel.release.scanners import scan_platform_rules


def test_secret_scan_redacts_value(tmp_path):
    secret = "api_key='abcdefghijklmnop'"
    (tmp_path / "config.py").write_text(secret, encoding="utf-8")

    findings = scan_platform_rules(tmp_path)

    assert len(findings) == 1
    payload = str(findings[0].to_dict())
    assert "abcdefghijklmnop" not in payload
    assert "redacted" in payload
    assert findings[0].evidence[0].authority.value == "PLATFORM"


def test_secret_scan_ignores_large_file(tmp_path):
    (tmp_path / "big.txt").write_text(
        "x" * 1_000_001 + "api_key='abcdefghijklmnop'",
        encoding="utf-8",
    )
    assert scan_platform_rules(tmp_path) == []


def test_secret_scan_does_not_follow_symlinks(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("api_key='abcdefghijklmnop'", encoding="utf-8")
    (repository / "linked.txt").symlink_to(outside)

    assert scan_platform_rules(repository) == []
