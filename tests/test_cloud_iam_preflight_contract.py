from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_preflight_checks_effective_project_permissions():
    s = (ROOT / 'deploy' / 'preflight.sh').read_text()
    for perm in [
        'resourcemanager.projects.setIamPolicy',
        'serviceusage.services.enable',
        'iam.serviceAccounts.create',
        'datastore.databases.create',
    ]:
        assert perm in s
    assert ':testIamPermissions' in s
    assert 'billing=enabled' in s


def test_bootstrap_checks_service_account_policy_permission():
    s = (ROOT / 'deploy' / 'bootstrap-gcp.sh').read_text()
    assert 'iam.serviceAccounts.setIamPolicy' in s
    assert 'roles/iam.serviceAccountAdmin' in s
    assert 'serviceAccounts/$sa:testIamPermissions' in s


def test_local_jury_demo_requires_go_123_or_newer():
    s = (ROOT / 'scripts' / 'demo-jury.sh').read_text()
    assert 'Go 1.23+' in s
    assert "(1,23)" in s.replace(' ', '')
