variable "aws_region" {
  description = "Region, w którym stoi manager i stawiam honeypota (ten sam, żeby uniknąć hairpinu ruchu przez EIP)."
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "Nazwa istniejącej pary kluczy EC2"
  type        = string
}

variable "admin_cidr" {
  description = : curl ifconfig.me"
  type        = string
}

# --- ISTNIEJĄCY MANAGER) ---

variable "manager_ip" {
  description = "Elastic IP managera. Honeypot będzie się z nim łączył."
  type        = string
}

variable "manager_security_group_id" {
  description = "ID grupy bezpieczeństwa managera"
  type        = string
}

# HONEYPOT

variable "honeypot_instance_type" {
  description = "Typ instancji honeypota. t3.small"
  type        = string
  default     = "t3.small"
}

variable "admin_ssh_port" {
  description = "Port prawdziwego SSH administracyjnego. MUSI być inny niż 22, bo 22 przejmuje przynęta Cowrie."
  type        = number
  default     = 22022
}

variable "wazuh_agent_name" {
  description = "Nazwa agenta widoczna na managerze."
  type        = string
  default     = "cowrie-honeypot"
}

variable "wazuh_agent_version" {
  description = "Przypięta wersja agenta Wazuh (ta sama co manager). apt-mark hold zablokuje auto-update."
  type        = string
  default     = "4.11.2-1"
}

variable "cowrie_ref" {
  description = "Git ref Cowrie do checkoutu. (np. v2.6.1)."
  type        = string
  default     = "v2.6.0"
}
