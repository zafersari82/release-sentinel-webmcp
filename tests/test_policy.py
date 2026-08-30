import pytest

from release_sentinel.policy.model import PolicyError, build_policy


def policy_document(**overrides):
    document = {
        "policy_id": "p",
        "revision": 1,
        "commands": [
            {
                "id": "c",
                "title": "check",
                "argv": ["/usr/bin/python3", "-V"],
                "cwd": ".",
                "timeout_seconds": 30,
                "severity": "HIGH",
                "blocking_on_failure": True,
            }
        ],
    }
    document.update(overrides)
    return document


def test_policy_hash_is_stable():
    assert build_policy(policy_document()).sha256 == build_policy(policy_document()).sha256


def test_policy_requires_absolute_executable():
    document = policy_document()
    document["commands"][0]["argv"] = ["python3", "-V"]

    with pytest.raises(PolicyError):
        build_policy(document)


def test_policy_rejects_cwd_escape():
    document = policy_document()
    document["commands"][0]["cwd"] = "../x"

    with pytest.raises(PolicyError):
        build_policy(document)


def test_policy_rejects_duplicate_ids():
    document = policy_document()
    document["commands"].append(dict(document["commands"][0]))

    with pytest.raises(PolicyError):
        build_policy(document)


@pytest.mark.parametrize("timeout", [0, 1801, True])
def test_policy_timeout_bounds(timeout):
    document = policy_document()
    document["commands"][0]["timeout_seconds"] = timeout

    with pytest.raises(PolicyError):
        build_policy(document)


@pytest.mark.parametrize("severity", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_policy_accepts_all_severities(severity):
    document = policy_document()
    document["commands"][0]["severity"] = severity

    assert build_policy(document).commands[0].severity.value == severity
