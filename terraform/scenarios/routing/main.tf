# Scenario "routing": is a server really reachable from the Internet?
# Every server below has a public IP and SSH open to 0.0.0.0/0. What differs is the ROUTE:
#   VPC a: a_public  -> route 0.0.0.0/0 to the Internet gateway   => reachable   (NET-01)
#          a_private -> route 0.0.0.0/0 only to a NAT gateway      => NOT reachable
#   VPC b: subnet without association -> the VPC's DEFAULT route table goes to the IGW => reachable (NET-01)
#   VPC c: subnet without association -> a custom MAIN route table goes to the IGW     => reachable (NET-01)
#   VPC d: an Internet gateway exists, but no route uses it        => NOT reachable
# Expected: 3 findings.

variable "ami" {
  type    = string
  default = "ami-0abcdef1234567890"
}

# ----- VPC a: public subnet (IGW route) and private subnet (NAT route) -----
resource "aws_vpc" "a" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_internet_gateway" "a" {
  vpc_id = aws_vpc.a.id
}

resource "aws_subnet" "a_public" {
  vpc_id     = aws_vpc.a.id
  cidr_block = "10.1.1.0/24"
}

resource "aws_subnet" "a_private" {
  vpc_id     = aws_vpc.a.id
  cidr_block = "10.1.2.0/24"
}

resource "aws_route_table" "a_public" {
  vpc_id = aws_vpc.a.id
}

resource "aws_route" "a_public_default" {
  route_table_id         = aws_route_table.a_public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.a.id
}

resource "aws_route_table_association" "a_public" {
  subnet_id      = aws_subnet.a_public.id
  route_table_id = aws_route_table.a_public.id
}

resource "aws_eip" "a_nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "a" {
  allocation_id = aws_eip.a_nat.id
  subnet_id     = aws_subnet.a_public.id
}

resource "aws_route_table" "a_private" {
  vpc_id = aws_vpc.a.id
}

resource "aws_route" "a_private_default" {
  route_table_id         = aws_route_table.a_private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.a.id
}

resource "aws_route_table_association" "a_private" {
  subnet_id      = aws_subnet.a_private.id
  route_table_id = aws_route_table.a_private.id
}

resource "aws_security_group" "a_ssh" {
  vpc_id = aws_vpc.a.id
}

resource "aws_vpc_security_group_ingress_rule" "a_ssh_world" {
  security_group_id = aws_security_group.a_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "a_public" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.a_public.id
  vpc_security_group_ids      = [aws_security_group.a_ssh.id]
  associate_public_ip_address = true
}

resource "aws_instance" "a_private" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.a_private.id
  vpc_security_group_ids      = [aws_security_group.a_ssh.id]
  associate_public_ip_address = true
}

# ----- VPC b: the default route table of the VPC routes to the IGW -----
resource "aws_vpc" "b" {
  cidr_block = "10.2.0.0/16"
}

resource "aws_internet_gateway" "b" {
  vpc_id = aws_vpc.b.id
}

resource "aws_default_route_table" "b" {
  default_route_table_id = aws_vpc.b.default_route_table_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.b.id
  }
}

resource "aws_subnet" "b_unassociated" {
  vpc_id     = aws_vpc.b.id
  cidr_block = "10.2.1.0/24"
}

resource "aws_security_group" "b_ssh" {
  vpc_id = aws_vpc.b.id
}

resource "aws_vpc_security_group_ingress_rule" "b_ssh_world" {
  security_group_id = aws_security_group.b_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "b" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.b_unassociated.id
  vpc_security_group_ids      = [aws_security_group.b_ssh.id]
  associate_public_ip_address = true
}

# ----- VPC c: a custom route table is made the MAIN one -----
resource "aws_vpc" "c" {
  cidr_block = "10.3.0.0/16"
}

resource "aws_internet_gateway" "c" {
  vpc_id = aws_vpc.c.id
}

resource "aws_route_table" "c_main" {
  vpc_id = aws_vpc.c.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.c.id
  }
}

resource "aws_main_route_table_association" "c" {
  vpc_id         = aws_vpc.c.id
  route_table_id = aws_route_table.c_main.id
}

resource "aws_subnet" "c_unassociated" {
  vpc_id     = aws_vpc.c.id
  cidr_block = "10.3.1.0/24"
}

resource "aws_security_group" "c_ssh" {
  vpc_id = aws_vpc.c.id
}

resource "aws_vpc_security_group_ingress_rule" "c_ssh_world" {
  security_group_id = aws_security_group.c_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "c" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.c_unassociated.id
  vpc_security_group_ids      = [aws_security_group.c_ssh.id]
  associate_public_ip_address = true
}

# ----- VPC d: Internet gateway without any route to it -----
resource "aws_vpc" "d" {
  cidr_block = "10.4.0.0/16"
}

resource "aws_internet_gateway" "d" {
  vpc_id = aws_vpc.d.id
}

resource "aws_subnet" "d_unassociated" {
  vpc_id     = aws_vpc.d.id
  cidr_block = "10.4.1.0/24"
}

resource "aws_security_group" "d_ssh" {
  vpc_id = aws_vpc.d.id
}

resource "aws_vpc_security_group_ingress_rule" "d_ssh_world" {
  security_group_id = aws_security_group.d_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_instance" "d" {
  ami                         = var.ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.d_unassociated.id
  vpc_security_group_ids      = [aws_security_group.d_ssh.id]
  associate_public_ip_address = true
}
