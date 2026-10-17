"""Tests for plan.py: reading resources and references from a Terraform plan."""

import pytest

from helpers import make_plan, resource
from iacgraph.plan import find_reference_strings, get_references, get_resources, load_plan, without_index

DEMO = "tests/fixtures/demo-insecure.plan.json"


def test_load_plan_reads_the_demo():
    plan = load_plan(DEMO)
    assert "resource_changes" in plan


def test_load_plan_rejects_a_file_that_is_not_a_plan(tmp_path):
    not_a_plan = tmp_path / "state.json"
    not_a_plan.write_text('{"values": {}}')
    with pytest.raises(ValueError):
        load_plan(not_a_plan)


def test_the_demo_has_31_resources_with_their_settings():
    resources = get_resources(load_plan(DEMO), [])
    assert len(resources) == 31
    web = resources["aws_instance.web"]
    assert web["type"] == "aws_instance"
    assert web["values"]["associate_public_ip_address"] is True
    assert "public_ip" in web["unknown"]  # AWS chooses the address at apply


def test_deleted_resources_and_data_sources_are_skipped():
    plan = make_plan(resource("aws_vpc.main"))
    plan["resource_changes"].append(
        {"address": "aws_vpc.old", "mode": "managed", "type": "aws_vpc", "change": {"actions": ["delete"]}}
    )
    plan["resource_changes"].append(
        {"address": "data.aws_ami.x", "mode": "data", "type": "aws_ami", "change": {"actions": ["read"]}}
    )
    assert list(get_resources(plan, [])) == ["aws_vpc.main"]


def test_resources_in_modules_are_skipped_with_a_warning():
    plan = make_plan(resource("aws_vpc.main"))
    plan["resource_changes"][0]["module_address"] = "module.network"
    warnings = []
    assert get_resources(plan, warnings) == {}
    assert "modules" in warnings[0]


def test_find_reference_strings_searches_nested_blocks():
    expression = [{"cidr_blocks": {"constant_value": ["0.0.0.0/0"]}, "gateway_id": {"references": ["aws_internet_gateway.main"]}}]
    assert find_reference_strings(expression) == ["aws_internet_gateway.main"]


def test_without_index():
    assert without_index("aws_subnet.public[0]") == "aws_subnet.public"
    assert without_index('aws_subnet.public["a"]') == "aws_subnet.public"
    assert without_index("aws_subnet.public") == "aws_subnet.public"


def test_the_web_server_refers_to_its_subnet_security_group_and_profile():
    plan = load_plan(DEMO)
    references = get_references(plan, get_resources(plan, []), [])
    web = {(attribute, target) for source, attribute, target in references if source == "aws_instance.web"}
    assert web == {
        ("subnet_id", "aws_subnet.public_a"),
        ("vpc_security_group_ids", "aws_security_group.web"),
        ("iam_instance_profile", "aws_iam_instance_profile.app"),
    }


def test_variables_and_data_sources_are_not_resources():
    plan = make_plan(resource("aws_instance.web", refs={"ami": ["var.ami", "data.aws_ami.al2023"]}))
    assert get_references(plan, get_resources(plan, []), []) == []


def test_a_reference_reaches_every_instance_created_with_count():
    plan = make_plan(
        resource("aws_subnet.public[0]"),
        resource("aws_subnet.public[1]"),
        resource("aws_db_subnet_group.main", refs={"subnet_ids": ["aws_subnet.public"]}),
    )
    plan["configuration"]["root_module"]["resources"][0]["address"] = "aws_subnet.public"
    references = get_references(plan, get_resources(plan, []), [])
    assert references == [
        ("aws_db_subnet_group.main", "subnet_ids", "aws_subnet.public[0]"),
        ("aws_db_subnet_group.main", "subnet_ids", "aws_subnet.public[1]"),
    ]


def test_a_reference_through_a_local_gives_a_warning():
    plan = make_plan(resource("aws_subnet.a", refs={"vpc_id": ["local.vpc_id"]}))
    warnings = []
    assert get_references(plan, get_resources(plan, []), warnings) == []
    assert "locals" in warnings[0]
