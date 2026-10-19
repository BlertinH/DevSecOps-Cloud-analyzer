Checkov 3.3.29

| Scenario | Checkov: all failed checks | Expected problems | iacgraph found | Checkov found (same rules) |
|---|---|---|---|---|
| demo-insecure | 22 | 5 | 5 | 2 |
| demo-secure | 20 | 0 | 0 | 0 |
| routing | 42 | 3 | 3 | 4 |
| public-ip | 35 | 1 | 1 | 1 |
| database | 47 | 10 | 10 | 7 |
| sg-rules | 61 | 4 | 4 | 2 |
| iam | 36 | 2 | 2 | 1 |

| Rule | iacgraph precision | iacgraph recall | Checkov TP | Checkov FP | Checkov FN | Checkov precision | Checkov recall |
|---|---|---|---|---|---|---|---|
| NET-01 | 1.00 | 1.00 | 8 | 1 | 2 | 0.89 | 0.80 |
| NET-02 | 1.00 | 1.00 | 1 | 1 | 0 | 0.50 | 1.00 |
| PATH-01 | 1.00 | 1.00 | 0 | 0 | 6 | - | 0.00 |
| CFG-01 | 1.00 | 1.00 | 5 | 0 | 0 | 1.00 | 1.00 |
| CFG-02 | 1.00 | 1.00 | 1 | 0 | 2 | 1.00 | 0.33 |

Checkov alarms that are not in expected.json:
- routing: NET-01 aws_vpc_security_group_ingress_rule.d_ssh_world
- database: NET-02 aws_db_instance.private_flag_on

Expected problems that Checkov did not find:
- demo-insecure: CFG-02 aws_iam_role_policy.app_s3
- demo-insecure: PATH-01 aws_db_instance.main
- demo-insecure: PATH-01 aws_s3_bucket.data
- database: PATH-01 aws_db_instance.flag_off
- database: PATH-01 aws_db_instance.internal
- database: PATH-01 aws_db_instance.private_flag_on
- database: PATH-01 aws_db_instance.public_open
- sg-rules: NET-01 aws_security_group_rule.legacy_ssh
- sg-rules: NET-01 aws_vpc_security_group_ingress_rule.all_traffic_world
- iam: CFG-02 aws_iam_role_policy.app_s3
