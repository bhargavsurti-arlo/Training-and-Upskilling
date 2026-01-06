#===============================================================================
# TASK 1: Highly Available Web App Using ALB + EC2 Auto Scaling
#===============================================================================
# This Terraform configuration creates a highly available web application
# infrastructure in AWS Mumbai region (ap-south-1) with the following components:
#
# 1. Application Load Balancer (ALB) - Distributes traffic across instances
# 2. Auto Scaling Group (ASG) - Maintains 2 EC2 instances, scales between 1-3
# 3. Launch Template - Defines EC2 instance configuration with Nginx
# 4. Target Group - Routes ALB traffic to healthy instances
# 5. Security Groups - Controls network access for ALB and EC2
# 6. CloudWatch Alarms - Triggers scaling based on CPU utilization
#
# Scaling Policies:
#   - Scale OUT: Add 1 instance when CPU > 60%
#   - Scale IN:  Remove 1 instance when CPU < 20%
#===============================================================================

#-------------------------------------------------------------------------------
# TERRAFORM CONFIGURATION
#-------------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

#-------------------------------------------------------------------------------
# AWS PROVIDER - Mumbai Region
#-------------------------------------------------------------------------------
provider "aws" {
  region     = "ap-south-1"
  access_key = "AKIAUX6LAIFILNNQGUOO"
  secret_key = "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"
}

#-------------------------------------------------------------------------------
# DATA SOURCES - Fetch existing AWS resources
#-------------------------------------------------------------------------------

# Get the default VPC in the region
data "aws_vpc" "default" {
  default = true
}

# Get all subnets in the default VPC (spread across multiple AZs)
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Get the latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

#-------------------------------------------------------------------------------
# SECURITY GROUPS
#-------------------------------------------------------------------------------

# Security Group for Application Load Balancer
# Allows HTTP (port 80) traffic from the internet
resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = data.aws_vpc.default.id

  # Inbound: Allow HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound: Allow all traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for EC2 Instances
# Only allows HTTP traffic from the ALB (not directly from internet)
resource "aws_security_group" "ec2" {
  name   = "ec2-sg"
  vpc_id = data.aws_vpc.default.id

  # Inbound: Allow HTTP only from ALB security group
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Outbound: Allow all traffic (for package updates, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#-------------------------------------------------------------------------------
# LAUNCH TEMPLATE - EC2 Instance Configuration
#-------------------------------------------------------------------------------

# Defines how EC2 instances are configured when launched by Auto Scaling
resource "aws_launch_template" "webapp" {
  name          = "webapp"
  image_id      = data.aws_ami.al2023.id  # Amazon Linux 2023
  instance_type = "t3.micro"               # Free tier eligible

  # Network configuration
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ec2.id]
  }

  # User data script - runs on instance launch
  # Installs Nginx and creates a web page showing instance metadata
  user_data = base64encode(<<-EOF
#!/bin/bash
# Install Nginx web server
dnf -y install nginx
systemctl enable nginx

# Get instance metadata using IMDSv2 (secure method)
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
IID=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
PRIVATE_IP=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

# Create HTML page with instance information
cat > /usr/share/nginx/html/index.html <<HTML
<h1>WebApp on NGINX</h1>
<p><b>Instance ID:</b> $IID</p>
<p><b>Region:</b> $REGION</p>
<p><b>Availability Zone:</b> $AZ</p>
<p><b>Private IP:</b> $PRIVATE_IP</p>
<p><b>Public IP:</b> $PUBLIC_IP</p>
HTML

# Start Nginx
systemctl start nginx
EOF
  )
}

#-------------------------------------------------------------------------------
# TARGET GROUP - Health Checks and Instance Registration
#-------------------------------------------------------------------------------

# Target Group for the ALB to route traffic to EC2 instances
resource "aws_lb_target_group" "webapp" {
  name     = "tg-webapp"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  # Health check configuration
  health_check {
    path                = "/"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
  }
}

#-------------------------------------------------------------------------------
# APPLICATION LOAD BALANCER
#-------------------------------------------------------------------------------

# Internet-facing ALB that distributes traffic across EC2 instances
resource "aws_lb" "webapp" {
  name               = "alb-webapp"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids  # Spans multiple AZs
}

# ALB Listener - Listens on port 80 and forwards to target group
resource "aws_lb_listener" "webapp" {
  load_balancer_arn = aws_lb.webapp.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webapp.arn
  }
}

#-------------------------------------------------------------------------------
# AUTO SCALING GROUP
#-------------------------------------------------------------------------------

# ASG maintains desired number of instances and replaces unhealthy ones
resource "aws_autoscaling_group" "webapp" {
  name                = "asg-webapp"
  desired_capacity    = 2    # Start with 2 instances
  min_size            = 1    # Minimum 1 instance
  max_size            = 3    # Maximum 3 instances
  vpc_zone_identifier = data.aws_subnets.default.ids  # Launch in multiple AZs
  target_group_arns   = [aws_lb_target_group.webapp.arn]

  launch_template {
    id      = aws_launch_template.webapp.id
    version = "$Latest"
  }
}

#-------------------------------------------------------------------------------
# AUTO SCALING POLICIES
#-------------------------------------------------------------------------------

# Scale Out Policy - Adds 1 instance when triggered
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out"
  autoscaling_group_name = aws_autoscaling_group.webapp.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1      # Add 1 instance
  cooldown               = 300    # Wait 5 minutes before next scaling action
}

# Scale In Policy - Removes 1 instance when triggered
resource "aws_autoscaling_policy" "scale_in" {
  name                   = "scale-in"
  autoscaling_group_name = aws_autoscaling_group.webapp.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1     # Remove 1 instance
  cooldown               = 300    # Wait 5 minutes before next scaling action
}

#-------------------------------------------------------------------------------
# CLOUDWATCH ALARMS - Trigger scaling based on CPU utilization
#-------------------------------------------------------------------------------

# Scale Out Alarm - Triggers when average CPU > 60% for 4 minutes
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2         # Number of periods to evaluate
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120       # 2 minutes per period
  statistic           = "Average"
  threshold           = 60        # 60% CPU threshold
  alarm_actions       = [aws_autoscaling_policy.scale_out.arn]
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp.name
  }
}

# Scale In Alarm - Triggers when average CPU < 20% for 4 minutes
resource "aws_cloudwatch_metric_alarm" "cpu_low" {
  alarm_name          = "cpu-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2         # Number of periods to evaluate
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120       # 2 minutes per period
  statistic           = "Average"
  threshold           = 20        # 20% CPU threshold
  alarm_actions       = [aws_autoscaling_policy.scale_in.arn]
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp.name
  }
}

#-------------------------------------------------------------------------------
# OUTPUTS
#-------------------------------------------------------------------------------

# The ALB DNS name to access the web application
output "alb_url" {
  description = "URL to access the web application"
  value       = "http://${aws_lb.webapp.dns_name}"
}
