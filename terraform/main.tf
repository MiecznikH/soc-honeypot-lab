########################################
# Dane pomocnicze
########################################

# Najnowszy obraz Ubuntu 22.04 (Canonical). 
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Domyślny VPC, docelowo własny.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

########################################
# FAZA 1 zrobiona ręcznie: EIP managera .
########################################

########################################
# FAZA 2 — Honeypot: EIP, grupa bezpieczeństwa, instancja
########################################

resource "aws_eip" "honeypot" {
  domain = "vpc"
  tags   = { Name = "cowrie-honeypot-eip" }
}

resource "aws_security_group" "honeypot" {
  name        = "cowrie-honeypot-sg"
  description = "Honeypot: Bait na 22 dla swiata, admin SSH tylko z admin IP"
  vpc_id      = data.aws_vpc.default.id

  # Bait: port 22 otwarty dla świata. iptables przekieruje go na 2222 (Cowrie).
  ingress {
    description = "Cowrie bait (redirected to 2222)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # PRAWDZIWY admin SSH - na porcie innym niż 22.
  ingress {
    description = "Admin SSH"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "Wychodzacy ruch (agent do manager, apt, AbuseIPDB itd.)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cowrie-honeypot-sg" }
}

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.honeypot_instance_type
  key_name               = var.key_name
  subnet_id              = tolist(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids = [aws_security_group.honeypot.id]

  user_data = templatefile("${path.module}/templates/honeypot_userdata.sh.tpl", {
    manager_ip          = var.manager_ip
    agent_name          = var.wazuh_agent_name
    admin_ssh_port      = var.admin_ssh_port
    wazuh_agent_version = var.wazuh_agent_version
    cowrie_ref          = var.cowrie_ref
  })

  # Zmiana user_data ma odtworzyć instancję (świeży bootstrap), a nie edytować w miejscu.
  user_data_replace_on_change = true

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = var.wazuh_agent_name }
}

resource "aws_eip_association" "honeypot" {
  instance_id   = aws_instance.honeypot.id
  allocation_id = aws_eip.honeypot.id
}

########################################
# Reguła na SG managera: wpuść agenta honeypota po jego stałym EIP
########################################

resource "aws_security_group_rule" "manager_from_honeypot" {
  description       = "Wazuh agent (honeypot) do manager: enrollment + events"
  type              = "ingress"
  from_port         = 1514
  to_port           = 1515
  protocol          = "tcp"
  security_group_id = var.manager_security_group_id
  cidr_blocks       = ["${aws_eip.honeypot.public_ip}/32"]
}
