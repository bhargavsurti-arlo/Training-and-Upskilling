#!/bin/bash
# AWS EC2 Inventory Management Portal - Deployment Script
# This script creates an EC2 instance in Ireland (eu-west-1) and deploys the web portal

set -e

# Configuration
REGION="eu-west-1"
INSTANCE_TYPE="t2.micro"  # Free tier eligible
KEY_NAME="ec2-inventory-key"
SECURITY_GROUP_NAME="ec2-inventory-sg"
INSTANCE_NAME="EC2-Inventory-Portal"

echo "=========================================="
echo "AWS EC2 Inventory Management Portal Setup"
echo "Region: $REGION (Ireland)"
echo "=========================================="

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &>/dev/null; then
    echo "Error: AWS CLI is not configured. Please run 'aws configure' first."
    exit 1
fi

echo ""
echo "[1/7] Creating Key Pair..."
# Create key pair if it doesn't exist
if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" &>/dev/null; then
    echo "Key pair '$KEY_NAME' already exists."
else
    aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --region "$REGION" \
        --query 'KeyMaterial' \
        --output text > "${KEY_NAME}.pem"
    chmod 400 "${KEY_NAME}.pem"
    echo "Key pair created and saved to ${KEY_NAME}.pem"
fi

echo ""
echo "[2/7] Creating Security Group..."
# Get default VPC
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)

# Create security group if it doesn't exist
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

if [ "$SG_ID" == "None" ] || [ -z "$SG_ID" ]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$SECURITY_GROUP_NAME" \
        --description "Security group for EC2 Inventory Portal" \
        --vpc-id "$VPC_ID" \
        --region "$REGION" \
        --query 'GroupId' \
        --output text)
    echo "Security group created: $SG_ID"
    
    # Add inbound rules
    echo "Adding inbound rules..."
    
    # SSH access
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"
    
    # HTTP access
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"
    
    # Flask app port
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 5000 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"
    
    echo "Inbound rules added (SSH:22, HTTP:80, Flask:5000)"
else
    echo "Security group already exists: $SG_ID"
fi

echo ""
echo "[3/7] Finding Amazon Linux 2023 AMI..."
# Get latest Amazon Linux 2023 AMI (free tier eligible)
AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)

echo "Using AMI: $AMI_ID"

echo ""
echo "[4/7] Creating IAM Role for EC2..."
# Create IAM role for EC2 to access other EC2 instances and SSM
ROLE_NAME="EC2InventoryPortalRole"
INSTANCE_PROFILE_NAME="EC2InventoryPortalProfile"

# Check if role exists
if ! aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    # Create trust policy
    cat > /tmp/trust-policy.json << 'EOF'
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
EOF

    aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document file:///tmp/trust-policy.json
    
    # Attach policies
    aws iam attach-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
    
    aws iam attach-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/AmazonSSMFullAccess
    
    # Create a custom policy for EC2 actions
    cat > /tmp/ec2-actions-policy.json << 'EOF'
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
EOF

    aws iam put-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-name "EC2ActionsPolicy" \
        --policy-document file:///tmp/ec2-actions-policy.json
    
    echo "IAM Role created: $ROLE_NAME"
else
    echo "IAM Role already exists: $ROLE_NAME"
fi

# Create instance profile if it doesn't exist
if ! aws iam get-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" &>/dev/null; then
    aws iam create-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"
    aws iam add-role-to-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --role-name "$ROLE_NAME"
    echo "Instance profile created: $INSTANCE_PROFILE_NAME"
    echo "Waiting for instance profile to be ready..."
    sleep 10
else
    echo "Instance profile already exists: $INSTANCE_PROFILE_NAME"
fi

echo ""
echo "[5/7] Creating User Data Script..."
# Create user data script for instance initialization
cat > /tmp/user-data.sh << 'USERDATA'
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

# The application files will be uploaded separately
# For now, create a placeholder

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

# Enable service (will start after files are uploaded)
systemctl daemon-reload
systemctl enable ec2-inventory

echo "Setup complete. Upload application files and start the service."
USERDATA

echo ""
echo "[6/7] Launching EC2 Instance..."
# Launch EC2 instance
INSTANCE_ID=$(aws ec2 run-instances \
    --region "$REGION" \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --iam-instance-profile Name="$INSTANCE_PROFILE_NAME" \
    --user-data file:///tmp/user-data.sh \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "Instance launched: $INSTANCE_ID"
echo "Waiting for instance to be running..."

aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

echo ""
echo "[7/7] Getting Instance Details..."
# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

PUBLIC_DNS=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicDnsName' \
    --output text)

echo ""
echo "=========================================="
echo "EC2 Instance Created Successfully!"
echo "=========================================="
echo ""
echo "Instance ID:    $INSTANCE_ID"
echo "Public IP:      $PUBLIC_IP"
echo "Public DNS:     $PUBLIC_DNS"
echo "Region:         $REGION"
echo "Instance Type:  $INSTANCE_TYPE (Free Tier)"
echo ""
echo "SSH Command:"
echo "  ssh -i ${KEY_NAME}.pem ec2-user@$PUBLIC_IP"
echo ""
echo "Next Steps:"
echo "1. Wait 2-3 minutes for the instance to complete initialization"
echo "2. Upload the application files:"
echo "   scp -i ${KEY_NAME}.pem -r app.py templates requirements.txt ec2-user@$PUBLIC_IP:/tmp/"
echo ""
echo "3. SSH into the instance and move files:"
echo "   ssh -i ${KEY_NAME}.pem ec2-user@$PUBLIC_IP"
echo "   sudo mv /tmp/app.py /tmp/templates /tmp/requirements.txt /opt/ec2-inventory/"
echo "   cd /opt/ec2-inventory && sudo /opt/ec2-inventory/venv/bin/pip install -r requirements.txt"
echo "   sudo systemctl start ec2-inventory"
echo ""
echo "4. Access the portal at:"
echo "   http://$PUBLIC_IP:5000"
echo ""
echo "=========================================="



