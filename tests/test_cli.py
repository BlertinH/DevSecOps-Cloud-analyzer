import json

from iacgraph.cli import main

INSECURE = "tests/fixtures/demo-insecure.plan.json"
SECURE = "tests/fixtures/demo-secure.plan.json"
INSECURE_POLICY = "terraform/demo-insecure/policy.json"
SECURE_POLICY = "terraform/demo-secure/policy.json"


def test_the_insecure_demo_is_blocked(capsys):
    assert main([INSECURE, "--policy", INSECURE_POLICY]) == 1
    output = capsys.readouterr().out
    assert "AP-1  internet -[tcp/22]-> aws_instance.web" in output
    assert "Gate: BLOCK" in output


def test_the_secure_demo_passes(capsys):
    assert main([SECURE, "--policy", SECURE_POLICY]) == 0
    assert "Gate: PASS" in capsys.readouterr().out


def test_the_insecure_demo_has_exactly_the_five_expected_findings(tmp_path):
    report = tmp_path / "report.json"
    main([INSECURE, "--policy", INSECURE_POLICY, "--format", "json", "--output", str(report)])
    findings = json.loads(report.read_text())["findings"]
    assert [(f["rule"], f["resource"], f["severity"]) for f in findings] == [
        ("CFG-01", "aws_db_instance.main", "high"),
        ("CFG-02", "aws_iam_role_policy.app_s3", "high"),
        ("NET-01", "aws_vpc_security_group_ingress_rule.web_ssh_world", "high"),
        ("PATH-01", "aws_db_instance.main", "high"),
        ("PATH-01", "aws_s3_bucket.data", "high"),
    ]


def test_an_error_fails_closed(tmp_path, capsys):
    """If the analysis cannot run, the exit code is 2, and the pipeline blocks."""
    assert main([str(tmp_path / "missing.json")]) == 2
    assert "error" in capsys.readouterr().err