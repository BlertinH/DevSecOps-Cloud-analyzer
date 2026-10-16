resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web tier"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project}-web-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "web_ssh_world" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from anywhere"
}

resource "aws_vpc_security_group_ingress_rule" "web_https_world" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from anywhere"
}

resource "aws_vpc_security_group_egress_rule" "web_all" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "All outbound"
}

resource "aws_security_group" "db" {
  name        = "${var.project}-db-sg"
  description = "Database tier"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project}-db-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "db_mysql_from_web" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
  description                  = "MySQL from web tier"
}
