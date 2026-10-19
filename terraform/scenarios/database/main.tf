# Scenario "database": can an attacker reach a database, directly or through a server?
# "app" is a public server with SSH open to the Internet (NET-01), so it is the attacker's way in.
#   public_open     -> public subnet + publicly_accessible + port open to 0.0.0.0/0 => NET-02 (critical)
#   flag_off        -> public subnet, but publicly_accessible = false               => not direct
#   private_flag_on -> publicly_accessible = true, but private subnet (no IGW route) => not direct
#   internal        -> private, accepts only the app's security group               => not direct
# All four accept connections from "app", so each is reachable in 2 steps:
#   internet -> app -> database                                                     => PATH-01 (x4)
# None sets storage_encrypted (default false) => CFG-01, raised to high on the attack path (x4).
# Expected: 10 findings.

variable "ami" {
  type    = string
  default = "ami-0abcdef1234567890"
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "pub_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.1.0/24"
  availability_zone = "eu-central-1a"
}

resource "aws_subnet" "pub_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.2.0/24"
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "priv_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.11.0/24"
  availability_zone = "eu-central-1a"
}

resource "aws_subnet" "priv_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.12.0/24"
  availability_zone = "eu-central-1b"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "pub_a" {
  subnet_id      = aws_subnet.pub_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "pub_b" {
  subnet_id      = aws_subnet.pub_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table_association" "priv_a" {
  subnet_id      = aws_subnet.priv_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "priv_b" {
  subnet_id      = aws_subnet.priv_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_db_subnet_group" "public" {
  name       = "probe-db-public"
  subnet_ids = [aws_subnet.pub_a.id, aws_subnet.pub_b.id]
}

resource "aws_db_subnet_group" "private" {
  name       = "probe-db-private"
  subnet_ids = [aws_subnet.priv_a.id, aws_subnet.priv_b.id]
}

resource "aws_security_group" "app" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_world" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_all" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "db_open" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "db_open_world" {
  security_group_id = aws_security_group.db_open.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
}

resource "aws_security_group" "db_from_app" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db_from_app.id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_instance" "app" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.pub_a.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = true
}

resource "aws_db_instance" "public_open" {
  identifier                  = "probe-public-open"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "probeadmin"
  manage_master_user_password = true
  skip_final_snapshot         = true
  db_subnet_group_name        = aws_db_subnet_group.public.name
  vpc_security_group_ids      = [aws_security_group.db_open.id]
  publicly_accessible         = true
}

resource "aws_db_instance" "flag_off" {
  identifier                  = "probe-flag-off"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "probeadmin"
  manage_master_user_password = true
  skip_final_snapshot         = true
  db_subnet_group_name        = aws_db_subnet_group.public.name
  vpc_security_group_ids      = [aws_security_group.db_open.id]
  publicly_accessible         = false
}

resource "aws_db_instance" "private_flag_on" {
  identifier                  = "probe-private-flag-on"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "probeadmin"
  manage_master_user_password = true
  skip_final_snapshot         = true
  db_subnet_group_name        = aws_db_subnet_group.private.name
  vpc_security_group_ids      = [aws_security_group.db_open.id]
  publicly_accessible         = true
}

resource "aws_db_instance" "internal" {
  identifier                  = "probe-internal"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "probeadmin"
  manage_master_user_password = true
  skip_final_snapshot         = true
  db_subnet_group_name        = aws_db_subnet_group.private.name
  vpc_security_group_ids      = [aws_security_group.db_from_app.id]
  publicly_accessible         = false
}
