output "manager_eip" {
  description = "Stały adres managera."
  value       = var.manager_ip
}

output "honeypot_eip" {
  description = "Stały adres honeypota."
  value       = aws_eip.honeypot.public_ip
}

output "honeypot_admin_ssh" {
  description = "Komenda do logowania administracyjnego (port przeniesiony z 22)."
  value       = "ssh -i <klucz> -p ${var.admin_ssh_port} ubuntu@${aws_eip.honeypot.public_ip}"
}

output "verify_logs_flowing" {
  description = "Sprawdzenie czy logi płyną"
  value       = "curl -k -u admin -X GET \"https://localhost:9200/wazuh-alerts-*/_count?pretty\" -H 'Content-Type: application/json' -d '{\"query\":{\"wildcard\":{\"location\":\"*cowrie*\"}}}'"
}
