# AWS EC2 Inventory Management Portal

A comprehensive web portal for managing EC2 instances across all AWS regions with Splunk maintenance capabilities.

## Features

### Main Dashboard
- View all EC2 instances across all AWS regions
- Filter by region, state, and search by name/instance type
- Real-time instance statistics
- Export inventory to CSV

### Instance Management
- **View Details**: Complete instance information including OS type, AMI details, volumes, etc.
- **Start/Stop/Reboot**: Basic instance lifecycle management
- **Terminate**: Safely terminate instances with confirmation

### Splunk Maintenance Dashboard
- **Splunk Status**: Check if Splunk is installed and running
- **Install Splunk**: Install Splunk Universal Forwarder
- **Upgrade Splunk**: Upgrade to a newer version
- **Remove Splunk**: Completely uninstall Splunk
- **Remove Duplicate Config**: Fix duplicate Splunk configurations

## Prerequisites

1. AWS CLI installed and configured
2. AWS credentials with appropriate permissions
3. PowerShell (Windows) or Bash (Linux/Mac)

## Deployment

### Quick Deploy (Windows PowerShell)

```powershell
# Run the deployment script
.\deploy.ps1
```

### Quick Deploy (Linux/Mac)

```bash
# Make the script executable
chmod +x deploy.sh

# Run the deployment script
./deploy.sh
```

### After Deployment

1. Wait 2-3 minutes for the EC2 instance to initialize
2. Upload and start the application:

```powershell
# Windows
.\upload-and-start.ps1 -PublicIP <YOUR_INSTANCE_PUBLIC_IP>
```

```bash
# Linux/Mac
chmod +x upload-and-start.sh
./upload-and-start.sh <YOUR_INSTANCE_PUBLIC_IP>
```

3. Access the portal at `http://<PUBLIC_IP>:5000`

## Architecture

```
EC2 Instance (eu-west-1 / Ireland)
├── Flask Application (Port 5000)
├── Gunicorn WSGI Server
├── IAM Role with EC2/SSM permissions
└── Security Group (22, 80, 5000)
```

## File Structure

```
Task-6/
├── app.py                    # Flask application
├── requirements.txt          # Python dependencies
├── templates/
│   ├── index.html           # Main dashboard
│   └── splunk_dashboard.html # Splunk maintenance dashboard
├── deploy.ps1               # Windows deployment script
├── deploy.sh                # Linux/Mac deployment script
├── upload-and-start.ps1     # Windows upload script
├── upload-and-start.sh      # Linux/Mac upload script
└── README.md                # This file
```

## Required IAM Permissions

The EC2 instance role needs:
- `AmazonEC2ReadOnlyAccess` - View EC2 instances
- `AmazonSSMFullAccess` - Execute commands via SSM
- Custom policy for:
  - `ec2:StartInstances`
  - `ec2:StopInstances`
  - `ec2:RebootInstances`
  - `ec2:TerminateInstances`

## Security Considerations

- The security group allows access from 0.0.0.0/0 - restrict this in production
- SSH key should be kept secure
- Consider adding HTTPS with a proper certificate
- Add authentication/authorization for production use

## Troubleshooting

### Application not starting
```bash
# Check service status
sudo systemctl status ec2-inventory

# View logs
sudo journalctl -u ec2-inventory -f
```

### Cannot connect to port 5000
- Check security group rules
- Verify the instance is running
- Check if gunicorn is running: `ps aux | grep gunicorn`

### SSM commands failing
- Ensure SSM Agent is installed and running
- Verify IAM role has SSM permissions
- Check instance is registered in SSM

## Cost

This deployment uses:
- **t2.micro** instance (Free Tier eligible)
- **EBS storage** (8GB, Free Tier eligible)

Estimated cost: **$0/month** within Free Tier limits

## License

MIT License



