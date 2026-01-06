# AWS EC2 Inventory Management Portal - PowerShell Deployment Script
# This script creates an EC2 instance in Ireland (eu-west-1) and deploys the web portal

$ErrorActionPreference = "Stop"

# Configuration
$REGION = "eu-west-1"
$INSTANCE_TYPE = "t2.micro"  # Free tier eligible
$KEY_NAME = "ec2-inventory-key"
$SECURITY_GROUP_NAME = "ec2-inventory-sg"
$INSTANCE_NAME = "EC2-Inventory-Portal"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "AWS EC2 Inventory Management Portal Setup" -ForegroundColor Cyan
Write-Host "Region: $REGION (Ireland)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if AWS CLI is configured
try {
    aws sts get-caller-identity | Out-Null
} catch {
    Write-Host "Error: AWS CLI is not configured. Please run 'aws configure' first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[1/7] Creating Key Pair..." -ForegroundColor Yellow

# Create key pair if it doesn't exist
$keyExists = aws ec2 describe-key-pairs --key-names $KEY_NAME --region $REGION 2>$null
if ($keyExists) {
    Write-Host "Key pair '$KEY_NAME' already exists." -ForegroundColor Green
} else {
    $keyMaterial = aws ec2 create-key-pair `
        --key-name $KEY_NAME `
        --region $REGION `
        --query 'KeyMaterial' `
        --output text
    $keyMaterial | Out-File -FilePath "$KEY_NAME.pem" -Encoding ASCII -NoNewline
    Write-Host "Key pair created and saved to $KEY_NAME.pem" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/7] Creating Security Group..." -ForegroundColor Yellow

# Get default VPC
$VPC_ID = aws ec2 describe-vpcs --region $REGION --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text

# Create security group if it doesn't exist
$SG_ID = aws ec2 describe-security-groups --region $REGION --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>$null

if (-not $SG_ID -or $SG_ID -eq "None") {
    $SG_ID = aws ec2 create-security-group `
        --group-name $SECURITY_GROUP_NAME `
        --description "Security group for EC2 Inventory Portal" `
        --vpc-id $VPC_ID `
        --region $REGION `
        --query 'GroupId' `
        --output text
    Write-Host "Security group created: $SG_ID" -ForegroundColor Green
    
    Write-Host "Adding inbound rules..." -ForegroundColor Yellow
    
    # SSH access
    aws ec2 authorize-security-group-ingress `
        --group-id $SG_ID `
        --protocol tcp `
        --port 22 `
        --cidr 0.0.0.0/0 `
        --region $REGION | Out-Null
    
    # HTTP access
    aws ec2 authorize-security-group-ingress `
        --group-id $SG_ID `
        --protocol tcp `
        --port 80 `
        --cidr 0.0.0.0/0 `
        --region $REGION | Out-Null
    
    # Flask app port
    aws ec2 authorize-security-group-ingress `
        --group-id $SG_ID `
        --protocol tcp `
        --port 5000 `
        --cidr 0.0.0.0/0 `
        --region $REGION | Out-Null
    
    Write-Host "Inbound rules added (SSH:22, HTTP:80, Flask:5000)" -ForegroundColor Green
} else {
    Write-Host "Security group already exists: $SG_ID" -ForegroundColor Green
}

Write-Host ""
Write-Host "[3/7] Finding Amazon Linux 2023 AMI..." -ForegroundColor Yellow

# Get latest Amazon Linux 2023 AMI
$AMI_ID = aws ec2 describe-images `
    --region $REGION `
    --owners amazon `
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" `
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' `
    --output text

Write-Host "Using AMI: $AMI_ID" -ForegroundColor Green

Write-Host ""
Write-Host "[4/7] Creating IAM Role for EC2..." -ForegroundColor Yellow

$ROLE_NAME = "EC2InventoryPortalRole"
$INSTANCE_PROFILE_NAME = "EC2InventoryPortalProfile"

# Check if role exists
$roleExists = aws iam get-role --role-name $ROLE_NAME 2>$null
if (-not $roleExists) {
    # Create trust policy
    $trustPolicy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
"@
    $trustPolicy | Out-File -FilePath "$env:TEMP\trust-policy.json" -Encoding ASCII
    
    aws iam create-role `
        --role-name $ROLE_NAME `
        --assume-role-policy-document "file://$env:TEMP\trust-policy.json" | Out-Null
    
    # Attach policies
    aws iam attach-role-policy `
        --role-name $ROLE_NAME `
        --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess | Out-Null
    
    aws iam attach-role-policy `
        --role-name $ROLE_NAME `
        --policy-arn arn:aws:iam::aws:policy/AmazonSSMFullAccess | Out-Null
    
    # Create custom policy for EC2 actions
    $ec2Policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "ec2:TerminateInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeImages",
                "ec2:DescribeVolumes",
                "ec2:DescribeRegions"
            ],
            "Resource": "*"
        }
    ]
}
"@
    $ec2Policy | Out-File -FilePath "$env:TEMP\ec2-actions-policy.json" -Encoding ASCII
    
    aws iam put-role-policy `
        --role-name $ROLE_NAME `
        --policy-name "EC2ActionsPolicy" `
        --policy-document "file://$env:TEMP\ec2-actions-policy.json" | Out-Null
    
    Write-Host "IAM Role created: $ROLE_NAME" -ForegroundColor Green
} else {
    Write-Host "IAM Role already exists: $ROLE_NAME" -ForegroundColor Green
}

# Create instance profile if it doesn't exist
$profileExists = aws iam get-instance-profile --instance-profile-name $INSTANCE_PROFILE_NAME 2>$null
if (-not $profileExists) {
    aws iam create-instance-profile --instance-profile-name $INSTANCE_PROFILE_NAME | Out-Null
    aws iam add-role-to-instance-profile `
        --instance-profile-name $INSTANCE_PROFILE_NAME `
        --role-name $ROLE_NAME | Out-Null
    Write-Host "Instance profile created: $INSTANCE_PROFILE_NAME" -ForegroundColor Green
    Write-Host "Waiting for instance profile to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
} else {
    Write-Host "Instance profile already exists: $INSTANCE_PROFILE_NAME" -ForegroundColor Green
}

Write-Host ""
Write-Host "[5/7] Creating User Data Script..." -ForegroundColor Yellow

# Create user data script
$userData = @"
#!/bin/bash
set -e

# Update system
dnf update -y

# Install Python and pip
dnf install -y python3 python3-pip git

# Create application directory
mkdir -p /opt/ec2-inventory
cd /opt/ec2-inventory

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask boto3 gunicorn

# Create app directory structure
mkdir -p templates

# Create systemd service
cat > /etc/systemd/system/ec2-inventory.service << 'EOF'
[Unit]
Description=EC2 Inventory Management Portal
After=network.target

[Service]
User=root
WorkingDirectory=/opt/ec2-inventory
Environment="PATH=/opt/ec2-inventory/venv/bin"
ExecStart=/opt/ec2-inventory/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ec2-inventory

echo "Setup complete. Upload application files and start the service."
"@

# Encode user data to base64
$userDataBytes = [System.Text.Encoding]::UTF8.GetBytes($userData)
$userDataBase64 = [Convert]::ToBase64String($userDataBytes)
$userDataBase64 | Out-File -FilePath "$env:TEMP\user-data.txt" -Encoding ASCII -NoNewline

Write-Host ""
Write-Host "[6/7] Launching EC2 Instance..." -ForegroundColor Yellow

# Launch EC2 instance
$INSTANCE_ID = aws ec2 run-instances `
    --region $REGION `
    --image-id $AMI_ID `
    --instance-type $INSTANCE_TYPE `
    --key-name $KEY_NAME `
    --security-group-ids $SG_ID `
    --iam-instance-profile Name=$INSTANCE_PROFILE_NAME `
    --user-data "file://$env:TEMP\user-data.txt" `
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" `
    --query 'Instances[0].InstanceId' `
    --output text

Write-Host "Instance launched: $INSTANCE_ID" -ForegroundColor Green
Write-Host "Waiting for instance to be running..." -ForegroundColor Yellow

aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region $REGION

Write-Host ""
Write-Host "[7/7] Getting Instance Details..." -ForegroundColor Yellow

# Get public IP
$PUBLIC_IP = aws ec2 describe-instances `
    --instance-ids $INSTANCE_ID `
    --region $REGION `
    --query 'Reservations[0].Instances[0].PublicIpAddress' `
    --output text

$PUBLIC_DNS = aws ec2 describe-instances `
    --instance-ids $INSTANCE_ID `
    --region $REGION `
    --query 'Reservations[0].Instances[0].PublicDnsName' `
    --output text

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "EC2 Instance Created Successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Instance ID:    $INSTANCE_ID" -ForegroundColor White
Write-Host "Public IP:      $PUBLIC_IP" -ForegroundColor White
Write-Host "Public DNS:     $PUBLIC_DNS" -ForegroundColor White
Write-Host "Region:         $REGION" -ForegroundColor White
Write-Host "Instance Type:  $INSTANCE_TYPE (Free Tier)" -ForegroundColor White
Write-Host ""
Write-Host "SSH Command:" -ForegroundColor Yellow
Write-Host "  ssh -i $KEY_NAME.pem ec2-user@$PUBLIC_IP" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Wait 2-3 minutes for the instance to complete initialization" -ForegroundColor White
Write-Host "2. Upload the application files:" -ForegroundColor White
Write-Host "   scp -i $KEY_NAME.pem -r app.py templates requirements.txt ec2-user@${PUBLIC_IP}:/tmp/" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. SSH into the instance and move files:" -ForegroundColor White
Write-Host "   ssh -i $KEY_NAME.pem ec2-user@$PUBLIC_IP" -ForegroundColor Cyan
Write-Host "   sudo mv /tmp/app.py /tmp/templates /tmp/requirements.txt /opt/ec2-inventory/" -ForegroundColor Cyan
Write-Host "   cd /opt/ec2-inventory && sudo /opt/ec2-inventory/venv/bin/pip install -r requirements.txt" -ForegroundColor Cyan
Write-Host "   sudo systemctl start ec2-inventory" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Access the portal at:" -ForegroundColor Yellow
Write-Host "   http://${PUBLIC_IP}:5000" -ForegroundColor Green
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green

# Save deployment info
$deploymentInfo = @"
Deployment Information
======================
Date: $(Get-Date)
Instance ID: $INSTANCE_ID
Public IP: $PUBLIC_IP
Public DNS: $PUBLIC_DNS
Region: $REGION
Key Pair: $KEY_NAME
Security Group: $SG_ID

Portal URL: http://${PUBLIC_IP}:5000
SSH Command: ssh -i $KEY_NAME.pem ec2-user@$PUBLIC_IP
"@
$deploymentInfo | Out-File -FilePath "deployment-info.txt" -Encoding UTF8
Write-Host "Deployment info saved to deployment-info.txt" -ForegroundColor Gray



