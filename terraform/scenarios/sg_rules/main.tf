# Scenario "sg_rules": does a firewall rule really open SSH/RDP to the Internet?
# All servers are public (public IP + route to the Internet gateway). What differs is the RULE:
#   range       -> tcp 0-65535 from 0.0.0.0/0 (contains 22)              => NET-01
#   all_traffic -> protocol "-1" (all traffic) from 0.0.0.0/0             => NET-01
#   corporate   -> SSH only from 203.0.113.0/24 (one company network)     => no finding
#   legacy      -> SSH from 0.0.0.0/0, old style aws_security_group_rule  => NET-01
#   inline      -> SSH from 0.0.0.0/0, ingress {} block inside the group  => NET-01
#   udp         -> DNS udp/53 from 0.0.0.0/0 (open, but not an admin port) => no finding
# Lateral movement (no finding, it only adds edges to the attack graph):
#   target accepts tcp/8080 from the VPC; src_with_egress may connect to it,
#   src_no_egress may not (its group has no outbound rule).
# Expected: 4 findings.

variable "ami" {
  type    = string
  default = "ami-0abcdef1234567890"
}

resource "aws_vpc" "main" {
  cidr_block = "10.30.0.0/16"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.30.1.0/24"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "range" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "range_world" {
  security_group_id = aws_security_group.range.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 0
  to_port           = 65535
  ip_protocol       = "tcp"
}

resource "aws_instance" "range" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.range.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "all_traffic" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "all_traffic_world" {
  security_group_id = aws_security_group.all_traffic.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "all_traffic" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.all_traffic.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "corporate" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "corporate_ssh" {
  security_group_id = aws_security_group.corporate.id
  cidr_ipv4         = "203.0.113.0/24"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "corporate" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.corporate.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "legacy" {
  vpc_id = aws_vpc.main.id
}

resource "aws_security_group_rule" "legacy_ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
}

resource "aws_instance" "legacy" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.legacy.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "inline" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "inline" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.inline.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "udp" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "udp_dns_world" {
  security_group_id = aws_security_group.udp.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_instance" "udp" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.udp.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "target" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "target_from_vpc" {
  security_group_id = aws_security_group.target.id
  cidr_ipv4         = "10.30.0.0/16"
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

resource "aws_instance" "target" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.target.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "no_egress" {
  vpc_id = aws_vpc.main.id
}

resource "aws_instance" "src_no_egress" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.no_egress.id]
  associate_public_ip_address = true
}

resource "aws_security_group" "with_egress" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_egress_rule" "with_egress_all" {
  security_group_id = aws_security_group.with_egress.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "src_with_egress" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.with_egress.id]
  associate_public_ip_address = true
}
