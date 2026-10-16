resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnets"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { Name = "${var.project}-db-subnets" }
}

resource "aws_db_instance" "main" {
  identifier                  = "${var.project}-db"
  engine                      = "mysql"
  engine_version              = "8.4"
  engine_lifecycle_support    = "open-source-rds-extended-support-disabled"
  instance_class              = var.db_instance_class
  allocated_storage           = 20
  db_name                     = "appdb"
  username                    = "admin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.main.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  publicly_accessible         = false
  storage_encrypted           = true
  skip_final_snapshot         = true

  tags = {
    Name      = "${var.project}-db"
    DataClass = "sensitive"
  }
}
