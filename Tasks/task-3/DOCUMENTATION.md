# AWS VPC Infrastructure with Terraform:

## Table of Contents
1. [Project Overview](project-overview)
2. [Architecture Design](architecture-design)
3. [Prerequisites](prerequisites)
4. [Infrastructure Components](infrastructure-components)
5. [Step-by-Step Implementation](step-by-step-implementation)
6. [Terraform Files Explanation](terraform-files-explanation)
7. [Deployment Process](deployment-process)
8. [Testing & Validation](testing--validation)
9. [Security Considerations](security-considerations)
10. [Cleanup Instructions](#cleanup-instructions)
---

## 1. Project Overview

### 1.1 Objective
Build a production-ready VPC infrastructure on AWS following networking best practices, including:
- A VPC with public and private subnets across multiple Availability Zones
- Proper routing with Internet Gateway and NAT Gateway
- A Bastion Host for secure access to private resources
- A private EC2 instance accessible only through the Bastion Host

### 1.2 Why This Architecture?
This architecture follows AWS Well-Architected Framework principles:
- **Security**: Private instances are not directly accessible from the internet
- **High Availability**: Resources spread across 2 Availability Zones
- **Scalability**: Subnets sized appropriately for future growth
- **Cost Optimization**: Single NAT Gateway (can be expanded for HA)

---

## 2. Architecture Design

### 2.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AWS Cloud (us-west-2)                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         VPC (10.0.0.0/16)                            │   │
│  │                                                                      │   │
│  │  ┌─────────────────────────────┐  ┌─────────────────────────────┐    │   │
│  │  │   Availability Zone A       │  │   Availability Zone B       │    │   │
│  │  │       (us-west-2a)          │  │       (us-west-2b)          │    │   │
│  │  │                             │  │                             │    │   │
│  │  │  ┌───────────────────────┐  │  │  ┌───────────────────────┐  │    │   │
│  │  │  │  Public Subnet 1      │  │  │  │  Public Subnet 2      │  │    │   │
│  │  │  │  10.0.1.0/24          │  │  │  │  10.0.2.0/24          │  │    │   │
│  │  │  │                       │  │  │  │                       │  │    │   │
│  │  │  │  ┌─────────────────┐  │  │  │  │                       │  │    │   │
│  │  │  │  │  Bastion Host   │  │  │  │  │                       │  │    │   │
│  │  │  │  │  (EC2 t2.micro) │  │  │  │  │                       │  │    │   │
│  │  │  │  │  35.88.165.81   │  │  │  │  │                       │  │    │   │
│  │  │  │  └─────────────────┘  │  │  │  │                       │  │    │   │
│  │  │  │                       │  │  │  │                       │  │    │   │
│  │  │  │  ┌─────────────────┐  │  │  │  │                       │  │    │   │
│  │  │  │  │  NAT Gateway    │  │  │  │  │                       │  │    │   │
│  │  │  │  │  52.88.223.214  │  │  │  │  │                       │  │    │   │
│  │  │  │  └─────────────────┘  │  │  │  │                       │  │    │   │
│  │  │  └───────────────────────┘  │  │  └───────────────────────┘  │    │   │
│  │  │                             │  │                             │    │   │
│  │  │  ┌───────────────────────┐  │  │  ┌───────────────────────┐  │    │   │
│  │  │  │  Private Subnet 1     │  │  │  │  Private Subnet 2     │  │    │   │
│  │  │  │  10.0.3.0/24          │  │  │  │  10.0.4.0/24          │  │    │   │
│  │  │  │                       │  │  │  │                       │  │    │   │
│  │  │  │  ┌─────────────────┐  │  │  │  │                       │  │    │   │
│  │  │  │  │ Private EC2     │  │  │  │  │                       │  │    │   │
│  │  │  │  │ (t2.micro)      │  │  │  │  │                       │  │    │   │
│  │  │  │  │ 10.0.3.196      │  │  │  │  │                       │  │    │   │
│  │  │  │  └─────────────────┘  │  │  │  │                       │  │    │   │
│  │  │  └───────────────────────┘  │  │  └───────────────────────┘  │    │   │
│  │  └─────────────────────────────┘  └─────────────────────────────┘    │   │
│  │                                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │   │
│  │  │                     Internet Gateway                            │ │   │ 
│  │  │                     (igw-0956595549e1f11c8)                     │ │   │
│  │  └─────────────────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                                  Internet
```

### 2.2 Network CIDR Allocation

| Component | CIDR Block | IP Range | Available IPs |
|-----------|------------|----------|---------------|
| VPC | 10.0.0.0/16 | 10.0.0.0 - 10.0.255.255 | 65,536 |
| Public Subnet 1 | 10.0.1.0/24 | 10.0.1.0 - 10.0.1.255 | 251* |
| Public Subnet 2 | 10.0.2.0/24 | 10.0.2.0 - 10.0.2.255 | 251* |
| Private Subnet 1 | 10.0.3.0/24 | 10.0.3.0 - 10.0.3.255 | 251* |
| Private Subnet 2 | 10.0.4.0/24 | 10.0.4.0 - 10.0.4.255 | 251* |

*AWS reserves 5 IPs per subnet for internal use.

---

## 3. Prerequisites

### 3.1 Software Requirements

| Software | Version Used | Purpose |
|----------|--------------|---------|
| AWS CLI | 2.32.16 | Authenticate with AWS |
| Terraform | 1.14.3 | Infrastructure as Code tool |
| OpenSSH | Built-in (Windows 10+) | SSH client for connections |

### 3.2 Installation Commands

```powershell
# Install AWS CLI
winget install -e --id Amazon.AWSCLI --accept-source-agreements --accept-package-agreements

# Install Terraform
winget install -e --id Hashicorp.Terraform --accept-source-agreements --accept-package-agreements

# Refresh PATH (required after installation)
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Verify installations
aws --version
terraform -version
```

### 3.3 AWS Configuration

```powershell
# Configure AWS credentials
aws configure

# Prompts for:
# AWS Access Key ID: <your-access-key>
# AWS Secret Access Key: <your-secret-key>
# Default region name: us-west-2
# Default output format: json

# Verify authentication
aws sts get-caller-identity
```

---

## 4. Infrastructure Components

### 4.1 Resources Created

| # | Resource Type | Resource Name | Purpose |
|---|---------------|---------------|---------|
| 1 | VPC | vpc-demo-vpc | Isolated virtual network |
| 2 | Internet Gateway | vpc-demo-igw | Public internet access |
| 3 | NAT Gateway | vpc-demo-nat-gw | Outbound internet for private subnets |
| 4 | Elastic IP | vpc-demo-nat-eip | Static IP for NAT Gateway |
| 5 | Public Subnet 1 | vpc-demo-public-subnet-1 | Hosts public resources (AZ-a) |
| 6 | Public Subnet 2 | vpc-demo-public-subnet-2 | Hosts public resources (AZ-b) |
| 7 | Private Subnet 1 | vpc-demo-private-subnet-1 | Hosts private resources (AZ-a) |
| 8 | Private Subnet 2 | vpc-demo-private-subnet-2 | Hosts private resources (AZ-b) |
| 9 | Public Route Table | vpc-demo-public-rt | Routes public subnet traffic |
| 10 | Private Route Table | vpc-demo-private-rt | Routes private subnet traffic |
| 11 | Route Table Associations | (4 associations) | Links subnets to route tables |
| 12 | Bastion Security Group | vpc-demo-bastion-sg | Controls Bastion access |
| 13 | Private Security Group | vpc-demo-private-sg | Controls private instance access |
| 14 | SSH Key Pair | bastion-key | SSH authentication |
| 15 | Bastion EC2 Instance | vpc-demo-bastion | Jump server for SSH |
| 16 | Private EC2 Instance | vpc-demo-private-instance | Backend server |

### 4.2 Component Explanations

#### VPC (Virtual Private Cloud)
- **What**: Logically isolated section of AWS cloud
- **Why**: Provides network isolation and control over IP addressing
- **CIDR**: 10.0.0.0/16 (65,536 IP addresses)

#### Internet Gateway (IGW)
- **What**: Horizontally scaled, redundant, highly available VPC component
- **Why**: Enables communication between VPC and the internet
- **Attachment**: Attached to the VPC

#### NAT Gateway
- **What**: Managed Network Address Translation service
- **Why**: Allows private subnet instances to access internet (for updates, patches) without exposing them to inbound internet traffic
- **Location**: Placed in public subnet, uses Elastic IP

#### Subnets
- **Public Subnets**: Have route to Internet Gateway, instances get public IPs
- **Private Subnets**: No direct internet access, route through NAT Gateway for outbound

#### Route Tables
- **Public Route Table**: 
  - 0.0.0.0/0 → Internet Gateway (all internet traffic goes through IGW)
- **Private Route Table**: 
  - 0.0.0.0/0 → NAT Gateway (outbound internet traffic goes through NAT)

#### Security Groups
- **Bastion SG**: Allows SSH (port 22) from anywhere (0.0.0.0/0)
- **Private SG**: Allows SSH (port 22) only from Bastion Security Group

#### Bastion Host
- **What**: A hardened EC2 instance in public subnet
- **Why**: Single point of entry for SSH access to private resources
- **Security**: Only SSH port open, all other ports blocked

---

## 5. Step-by-Step Implementation

### Step 1: Project Setup
Created project directory:
```powershell
New-Item -ItemType Directory -Force -Path "C:\Users\112557\OneDrive - Arrow Electronics, Inc\Desktop\Tasks\Task-2"
```

### Step 2: Create Terraform Configuration Files
Created 6 Terraform files:
- `providers.tf` - AWS provider configuration
- `variables.tf` - Input variables
- `vpc.tf` - VPC, subnets, gateways, route tables
- `security_groups.tf` - Security groups
- `ec2.tf` - EC2 instances and SSH key
- `outputs.tf` - Output values

### Step 3: Initialize Terraform
```powershell
cd "C:\Users\112557\OneDrive - Arrow Electronics, Inc\Desktop\Tasks\Task-2"
terraform init
```
This downloads required providers:
- hashicorp/aws v5.100.0
- hashicorp/tls v4.1.0
- hashicorp/local v2.6.1

### Step 4: Review Plan
```powershell
terraform plan
```
Shows 21 resources to be created.

### Step 5: Deploy Infrastructure
```powershell
terraform apply -auto-approve
```
Creates all resources in approximately 2-3 minutes.

### Step 6: Verify Deployment
Terraform outputs provide connection details:
- Bastion Public IP
- Private Instance Private IP
- SSH commands

---

## 6. Terraform Files Explanation

### 6.1 providers.tf
```hcl
terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
```
**Purpose**: Defines required Terraform version and providers:
- **aws**: Creates AWS resources
- **tls**: Generates SSH key pair
- **local**: Saves SSH private key to local file

### 6.2 variables.tf
```hcl
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "vpc-demo"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
  default     = "bastion-key"
}
```
**Purpose**: Centralizes configuration values for easy modification.

### 6.3 vpc.tf
**Purpose**: Creates core networking infrastructure.

Key Resources:
1. **aws_vpc.main**: Creates the VPC with DNS support enabled
2. **aws_internet_gateway.main**: Attaches IGW to VPC
3. **aws_subnet.public**: Creates 2 public subnets with auto-assign public IP
4. **aws_subnet.private**: Creates 2 private subnets
5. **aws_eip.nat**: Allocates Elastic IP for NAT Gateway
6. **aws_nat_gateway.main**: Creates NAT Gateway in public subnet
7. **aws_route_table.public/private**: Defines routing rules
8. **aws_route_table_association**: Associates subnets with route tables

### 6.4 security_groups.tf
**Purpose**: Defines firewall rules for EC2 instances.

**Bastion Security Group**:
- Ingress: SSH (22) from 0.0.0.0/0
- Egress: All traffic allowed

**Private Security Group**:
- Ingress: SSH (22) from Bastion Security Group only
- Egress: All traffic allowed

### 6.5 ec2.tf
**Purpose**: Creates EC2 instances and SSH key pair.

Key Resources:
1. **data.aws_ami.amazon_linux**: Finds latest Amazon Linux 2023 AMI
2. **tls_private_key.ssh**: Generates 4096-bit RSA key pair
3. **aws_key_pair.main**: Uploads public key to AWS
4. **local_file.private_key**: Saves private key locally
5. **aws_instance.bastion**: Creates Bastion Host in public subnet
6. **aws_instance.private**: Creates private instance in private subnet

### 6.6 outputs.tf
**Purpose**: Displays useful information after deployment.

Outputs include:
- VPC ID
- Subnet IDs
- Bastion Public IP/DNS
- Private Instance IP
- NAT Gateway IP
- SSH connection commands

---

## 7. Deployment Process

### 7.1 Terraform Workflow

```
┌─────────────────┐
│  terraform init │ ──► Downloads providers, initializes backend
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  terraform plan │ ──► Shows what will be created/changed
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ terraform apply │ ──► Creates/updates infrastructure
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Outputs      │ ──► Displays connection information
└─────────────────┘
```

### 7.2 Resource Creation Order

Terraform automatically determines dependencies:

1. VPC (no dependencies)
2. Internet Gateway (depends on VPC)
3. Subnets (depends on VPC)
4. Security Groups (depends on VPC)
5. Elastic IP (no dependencies)
6. NAT Gateway (depends on IGW, EIP, Public Subnet)
7. Route Tables (depends on VPC, IGW, NAT)
8. Route Table Associations (depends on Subnets, Route Tables)
9. Key Pair (no dependencies)
10. EC2 Instances (depends on Subnets, Security Groups, Key Pair)

### 7.3 Deployment Output

```
Apply complete! Resources: 21 added, 0 changed, 0 destroyed.

Outputs:

bastion_public_dns = "ec2-35-88-165-81.us-west-2.compute.amazonaws.com"
bastion_public_ip = "35.88.165.81"
nat_gateway_ip = "52.88.223.214"
private_instance_private_ip = "10.0.3.196"
private_subnet_ids = [
  "subnet-05e4b96d9537be156",
  "subnet-05e8073804b435dd6",
]
public_subnet_ids = [
  "subnet-0a70b01259adcaa5c",
  "subnet-069172d0374858280",
]
ssh_key_file = "./bastion-key.pem"
ssh_to_bastion = "ssh -i bastion-key.pem ec2-user@35.88.165.81"
vpc_id = "vpc-0f11cdb3290e9e03f"
```

---

## 8. Testing & Validation

### 8.1 Test 1: SSH to Bastion Host

**Command**:
```powershell
ssh -i C:\Users\112557\bastion-key.pem -o StrictHostKeyChecking=no ec2-user@35.88.165.81 "hostname; whoami; echo 'Bastion connection successful!'"
```

**Expected Output**:
```
ip-10-0-1-224.us-west-2.compute.internal
ec2-user
Bastion connection successful!
```

**What This Validates**:
- Bastion Host is running
- Security Group allows SSH from internet
- SSH key pair is working
- Public subnet has internet connectivity

### 8.2 Test 2: SSH to Private Instance via Bastion

**Command**:
```powershell
ssh -i C:\Users\112557\bastion-key.pem -o StrictHostKeyChecking=no -o "ProxyCommand=ssh -i C:\Users\112557\bastion-key.pem -o StrictHostKeyChecking=no -W %h:%p ec2-user@35.88.165.81" ec2-user@10.0.3.196 "hostname; whoami; echo 'Private instance connection successful!'"
```

**Expected Output**:
```
ip-10-0-3-196.us-west-2.compute.internal
ec2-user
Private instance connection successful!
```

**What This Validates**:
- Private instance is running
- Private Security Group allows SSH from Bastion
- SSH ProxyCommand/Jump Host works correctly
- Private subnet routing is correct

### 8.3 Test 3: Internet Access from Private Instance

```bash
# From private instance (after SSH through Bastion)
curl -I https://aws.amazon.com
```

**What This Validates**:
- NAT Gateway is working
- Private route table routes to NAT Gateway
- Outbound internet access works

---

## 9. Security Considerations

### 9.1 Security Best Practices Implemented

| Practice | Implementation |
|----------|----------------|
| Principle of Least Privilege | Private SG only allows SSH from Bastion SG |
| Defense in Depth | Multiple layers: VPC, Subnets, Security Groups |
| No Direct Internet Access | Private instances have no public IPs |
| Bastion Host Pattern | Single controlled entry point |
| Key-Based Authentication | SSH key pair, no password authentication |

### 9.2 Security Recommendations for Production

1. **Restrict Bastion SSH Access**: Change `0.0.0.0/0` to your specific IP
2. **Enable VPC Flow Logs**: For network traffic monitoring
3. **Use AWS Systems Manager Session Manager**: Alternative to Bastion Host
4. **Implement Multi-Factor Authentication**: For AWS console access
5. **Regular Key Rotation**: Rotate SSH keys periodically
6. **Enable CloudTrail**: For API activity logging

### 9.3 Security Group Rules Summary

**Bastion Security Group (vpc-demo-bastion-sg)**:
| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| Inbound | TCP | 22 | 0.0.0.0/0 | SSH access |
| Outbound | All | All | 0.0.0.0/0 | All traffic |

**Private Security Group (vpc-demo-private-sg)**:
| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| Inbound | TCP | 22 | Bastion SG | SSH from Bastion only |
| Outbound | All | All | 0.0.0.0/0 | All traffic (via NAT) |

---

## 10. Cleanup Instructions

### 10.1 Destroy All Resources

```powershell
cd "C:\Users\112557\OneDrive - Arrow Electronics, Inc\Desktop\Tasks\Task-2"
terraform destroy -auto-approve
```

### 10.2 What Gets Deleted

All 21 resources created by Terraform:
- VPC and all networking components
- EC2 instances
- Security groups
- NAT Gateway and Elastic IP
- SSH key pair (from AWS, local file remains)


## Appendix A: Resource IDs (This Deployment)

| Resource | ID |
|----------|-----|
| VPC | vpc-0f11cdb3290e9e03f |
| Internet Gateway | igw-0956595549e1f11c8 |
| NAT Gateway | nat-0a20df0f2c8446061 |
| Elastic IP | eipalloc-02d879df71c014a43 |
| Public Subnet 1 | subnet-0a70b01259adcaa5c |
| Public Subnet 2 | subnet-069172d0374858280 |
| Private Subnet 1 | subnet-05e4b96d9537be156 |
| Private Subnet 2 | subnet-05e8073804b435dd6 |
| Public Route Table | rtb-05d6ddef2fede5446 |
| Private Route Table | rtb-0d1b9ae7d83287fc4 |
| Bastion Security Group | sg-01493cbad5fe2588b |
| Private Security Group | sg-0818000a8e16092a6 |
| Bastion EC2 Instance | i-08007e7ad341d1b81 |
| Private EC2 Instance | i-0e9b509c50167b139 |

## Appendix B: Files Structure

C:\Users\112557\OneDrive - Arrow Electronics, Inc\Desktop\Tasks\Task-2\
├── providers.tf          # Provider configuration
├── variables.tf          # Input variables
├── vpc.tf                # VPC, subnets, gateways, routes
├── security_groups.tf    # Security group definitions
├── ec2.tf                # EC2 instances and SSH key
├── outputs.tf            # Output definitions
├── bastion-key.pem       # SSH private key (generated)
├── terraform.tfstate     # Terraform state file
├── terraform.tfstate.backup
├── .terraform/           # Provider plugins
├── .terraform.lock.hcl   # Provider version lock
└── DOCUMENTATION.md      # This file

