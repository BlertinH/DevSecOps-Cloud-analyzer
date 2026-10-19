# Scenario "public_ip": does a server really get a public IP address?
# All servers are in subnets that route to the Internet gateway, all have SSH open to 0.0.0.0/0.
#   inherits_auto  -> subnet "auto" gives public IPs (map_public_ip_on_launch) => public  (NET-01)
#   opt_out        -> subnet "auto", but associate_public_ip_address = false   => private
#   opt_in         -> subnet "manual", but associate_public_ip_address = true  => public  (NET-01)
#   none           -> subnet "manual", nothing set                             => private
#   with_eip       -> an Elastic IP points directly at the instance            => public  (NET-01)
#   with_eip_assoc -> an Elastic IP joined through aws_eip_association        => public  (NET-01)
# Expected: 4 findings.

variable "ami" {
  type    = string
  default = "ami-0abcdef1234567890"
}

resource "aws_vpc" "main" {
  cidr_block = "10.10.0.0/16"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_subnet" "auto" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.10.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "manual" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.10.2.0/24"
  map_public_ip_on_launch = false
}

resource "aws_route_table_association" "auto" {
  subnet_id      = aws_subnet.auto.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "manual" {
  subnet_id      = aws_subnet.manual.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "ssh" {
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "ssh_world" {
  security_group_id = aws_security_group.ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "inherits_auto" {
  ami                    = var.ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.auto.id
  vpc_security_group_ids = [aws_security_group.ssh.id]
}

resource "aws_instance" "opt_out" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.auto.id
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  associate_public_ip_address = false
}

resource "aws_instance" "opt_in" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.manual.id
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  associate_public_ip_address = true
}

resource "aws_instance" "none" {
  ami                    = var.ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.manual.id
  vpc_security_group_ids = [aws_security_group.ssh.id]
}

resource "aws_instance" "with_eip" {
  ami                    = var.ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.manual.id
  vpc_security_group_ids = [aws_security_group.ssh.id]
}

resource "aws_eip" "direct" {
  domain   = "vpc"
  instance = aws_instance.with_eip.id
}

resource "aws_instance" "with_eip_assoc" {
  ami                    = var.ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.manual.id
  vpc_security_group_ids = [aws_security_group.ssh.id]
}

resource "aws_eip" "associated" {
  domain = "vpc"
}

resource "aws_eip_association" "associated" {
  instance_id   = aws_instance.with_eip_assoc.id
  allocation_id = aws_eip.associated.id
}
