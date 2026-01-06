output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "Public Subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private Subnet IDs"
  value       = aws_subnet.private[*].id
}

output "bastion_public_ip" {
  description = "Bastion Host Public IP"
  value       = aws_instance.bastion.public_ip
}

output "bastion_public_dns" {
  description = "Bastion Host Public DNS"
  value       = aws_instance.bastion.public_dns
}

output "private_instance_private_ip" {
  description = "Private EC2 Instance Private IP"
  value       = aws_instance.private.private_ip
}

output "nat_gateway_ip" {
  description = "NAT Gateway Public IP"
  value       = aws_eip.nat.public_ip
}

output "ssh_key_file" {
  description = "Path to SSH private key"
  value       = local_file.private_key.filename
}

output "ssh_to_bastion" {
  description = "SSH command to connect to Bastion"
  value       = "ssh -i bastion-key.pem ec2-user@${aws_instance.bastion.public_ip}"
}

output "ssh_to_private_via_bastion" {
  description = "SSH command to connect to Private instance through Bastion"
  value       = "ssh -i bastion-key.pem -o ProxyCommand=\"ssh -i bastion-key.pem -W %h:%p ec2-user@${aws_instance.bastion.public_ip}\" ec2-user@${aws_instance.private.private_ip}"
}

