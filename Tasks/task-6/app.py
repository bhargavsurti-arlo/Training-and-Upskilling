#!/usr/bin/env python3
"""
AWS EC2 Inventory Management Portal
A comprehensive web portal for managing EC2 instances across all AWS regions
with Splunk maintenance capabilities.
"""

from flask import Flask, render_template, jsonify, request
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json
from datetime import datetime
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# All AWS regions
AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2',
    'eu-north-1', 'eu-south-1', 'eu-south-2',
    'ap-south-1', 'ap-south-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-east-1',
    'sa-east-1', 'ca-central-1', 'ca-west-1',
    'me-south-1', 'me-central-1',
    'af-south-1',
    'il-central-1'
]

# Common regions for quick loading (subset of most used regions)
QUICK_REGIONS = [
    'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-south-1'
]

def get_ec2_client(region):
    """Get EC2 client for a specific region"""
    try:
        return boto3.client('ec2', region_name=region)
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return None

def get_ssm_client(region):
    """Get SSM client for a specific region"""
    try:
        return boto3.client('ssm', region_name=region)
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return None

import time

def setup_ssm_agent_info(instance_id, region):
    """
    Get information needed for manual SSM Agent setup.
    This function does NOT restart the instance.
    Returns manual installation instructions since automatic installation requires SSH access.
    """
    try:
        ec2 = get_ec2_client(region)
        if ec2 is None:
            return {'success': False, 'error': 'EC2 client not available'}
        
        # Get instance details
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        public_ip = instance.get('PublicIpAddress', 'N/A')
        private_ip = instance.get('PrivateIpAddress', 'N/A')
        image_id = instance.get('ImageId', '')
        
        # Try to determine OS from AMI
        os_type = 'Linux'
        try:
            ami_response = ec2.describe_images(ImageIds=[image_id])
            if ami_response['Images']:
                ami_name = ami_response['Images'][0].get('Name', '').lower()
                ami_desc = ami_response['Images'][0].get('Description', '').lower()
                
                if 'ubuntu' in ami_name or 'ubuntu' in ami_desc:
                    os_type = 'Ubuntu'
                elif 'debian' in ami_name or 'debian' in ami_desc:
                    os_type = 'Debian'
                elif 'rhel' in ami_name or 'red hat' in ami_desc:
                    os_type = 'RHEL'
                elif 'centos' in ami_name:
                    os_type = 'CentOS'
                elif 'amzn' in ami_name or 'amazon' in ami_name:
                    os_type = 'Amazon Linux'
                elif 'suse' in ami_name or 'sles' in ami_desc:
                    os_type = 'SUSE'
        except:
            pass
        
        return {
            'success': True,
            'requires_manual': True,
            'instance_id': instance_id,
            'public_ip': public_ip,
            'private_ip': private_ip,
            'os_type': os_type,
            'message': 'Manual SSM Agent installation required (no restart needed)'
        }
        
    except ClientError as e:
        return {'success': False, 'error': str(e)}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def setup_ssm_agent(instance_id, region):
    """
    Provides information for SSM Agent setup - NO RESTART, NO SSH REQUIRED.
    The IAM role has already been attached. If SSM Agent is already installed,
    it will register automatically. If not, manual installation is needed.
    """
    # Get instance info for manual instructions
    info = setup_ssm_agent_info(instance_id, region)
    
    return {
        'success': False,
        'requires_manual': True,
        'error': 'SSM Agent needs to be installed manually (no automatic installation to avoid service disruption)',
        'instance_info': info,
        'manual_instructions': f'''
SSM Agent Manual Installation (NO RESTART REQUIRED)
====================================================

Instance: {instance_id}
Public IP: {info.get('public_ip', 'N/A')}
Private IP: {info.get('private_ip', 'N/A')}
Detected OS: {info.get('os_type', 'Linux')}

STEP 1: SSH into the instance
-----------------------------
ssh -i your-key.pem ec2-user@{info.get('public_ip', 'INSTANCE_IP')}

STEP 2: Install SSM Agent (based on your OS)
---------------------------------------------
For Amazon Linux/RHEL/CentOS:
  sudo yum install -y amazon-ssm-agent
  sudo systemctl enable amazon-ssm-agent
  sudo systemctl start amazon-ssm-agent

For Ubuntu:
  sudo snap install amazon-ssm-agent --classic
  sudo snap start amazon-ssm-agent

For Debian:
  wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
  sudo dpkg -i amazon-ssm-agent.deb
  sudo systemctl start amazon-ssm-agent

STEP 3: Verify SSM Agent is running
------------------------------------
  sudo systemctl status amazon-ssm-agent

STEP 4: Return here and click "Install Splunk" again
-----------------------------------------------------
The IAM role has already been attached. Once SSM Agent is running,
it will register automatically and Splunk installation can proceed.
'''
    }

def wait_for_ssm_registration(instance_id, region, max_wait=180):
    """Wait for an instance to register with SSM"""
    ssm = get_ssm_client(region)
    if ssm is None:
        return False
    
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            response = ssm.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )
            if response['InstanceInformationList']:
                if response['InstanceInformationList'][0].get('PingStatus') == 'Online':
                    return True
        except ClientError:
            pass
        time.sleep(10)
    
    return False

def ensure_iam_role(instance_id, region):
    """Ensure instance has an IAM role with SSM permissions"""
    try:
        ec2 = get_ec2_client(region)
        iam = boto3.client('iam')
        
        # Check if instance already has a profile
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        if instance.get('IamInstanceProfile'):
            return {'success': True, 'message': 'IAM profile already attached'}
        
        # Create role if it doesn't exist
        role_name = 'EC2-SSM-Role'
        profile_name = 'EC2-SSM-Profile'
        
        try:
            iam.get_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            # Create the role
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
            )
        
        # Create instance profile if it doesn't exist
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
        except iam.exceptions.NoSuchEntityException:
            iam.create_instance_profile(InstanceProfileName=profile_name)
            iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            time.sleep(10)  # Wait for profile to be ready
        
        # Associate profile with instance
        ec2.associate_iam_instance_profile(
            InstanceId=instance_id,
            IamInstanceProfile={'Name': profile_name}
        )
        
        return {'success': True, 'message': 'IAM profile attached'}
        
    except ClientError as e:
        if 'already has an IAM role' in str(e) or 'association already exists' in str(e):
            return {'success': True, 'message': 'IAM profile already attached'}
        return {'success': False, 'error': str(e)}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_all_instances(regions=None, filters=None):
    """Get all EC2 instances from specified regions"""
    if regions is None:
        regions = AWS_REGIONS
    
    all_instances = []
    
    for region in regions:
        try:
            ec2 = get_ec2_client(region)
            if ec2 is None:
                continue
                
            paginator = ec2.get_paginator('describe_instances')
            
            ec2_filters = []
            if filters:
                ec2_filters = filters
            
            for page in paginator.paginate(Filters=ec2_filters):
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Get instance name from tags
                        name = ''
                        tags = instance.get('Tags', [])
                        for tag in tags:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                        
                        instance_data = {
                            'instance_id': instance['InstanceId'],
                            'name': name,
                            'instance_type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'region': region,
                            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', ''),
                            'private_ip': instance.get('PrivateIpAddress', ''),
                            'public_ip': instance.get('PublicIpAddress', ''),
                            'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else '',
                            'platform': instance.get('Platform', 'Linux'),
                            'architecture': instance.get('Architecture', ''),
                            'vpc_id': instance.get('VpcId', ''),
                            'subnet_id': instance.get('SubnetId', ''),
                            'security_groups': [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                            'key_name': instance.get('KeyName', ''),
                            'ami_id': instance.get('ImageId', ''),
                            'root_device_type': instance.get('RootDeviceType', ''),
                            'virtualization_type': instance.get('VirtualizationType', ''),
                            'tags': {tag['Key']: tag['Value'] for tag in tags},
                            'monitoring': instance.get('Monitoring', {}).get('State', ''),
                            'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn', ''),
                            'ebs_optimized': instance.get('EbsOptimized', False)
                        }
                        all_instances.append(instance_data)
        except ClientError as e:
            logger.error(f"Error fetching instances from {region}: {e}")
            continue
        except Exception as e:
            logger.error(f"Unexpected error for {region}: {e}")
            continue
    
    return all_instances

def get_instance_details(instance_id, region):
    """Get detailed information about a specific instance"""
    try:
        ec2 = get_ec2_client(region)
        if ec2 is None:
            return None
            
        response = ec2.describe_instances(InstanceIds=[instance_id])
        
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            
            # Get AMI details
            ami_info = {}
            try:
                ami_response = ec2.describe_images(ImageIds=[instance.get('ImageId', '')])
                if ami_response['Images']:
                    ami = ami_response['Images'][0]
                    ami_info = {
                        'name': ami.get('Name', ''),
                        'description': ami.get('Description', ''),
                        'os_type': ami.get('PlatformDetails', ''),
                        'architecture': ami.get('Architecture', ''),
                        'root_device_type': ami.get('RootDeviceType', ''),
                        'virtualization_type': ami.get('VirtualizationType', '')
                    }
            except:
                pass
            
            # Get volume details
            volumes = []
            for bdm in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in bdm:
                    try:
                        vol_response = ec2.describe_volumes(VolumeIds=[bdm['Ebs']['VolumeId']])
                        if vol_response['Volumes']:
                            vol = vol_response['Volumes'][0]
                            volumes.append({
                                'volume_id': vol['VolumeId'],
                                'device_name': bdm['DeviceName'],
                                'size': vol['Size'],
                                'volume_type': vol['VolumeType'],
                                'state': vol['State'],
                                'encrypted': vol.get('Encrypted', False)
                            })
                    except:
                        pass
            
            name = ''
            tags = instance.get('Tags', [])
            for tag in tags:
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
            
            return {
                'instance_id': instance['InstanceId'],
                'name': name,
                'instance_type': instance['InstanceType'],
                'state': instance['State']['Name'],
                'region': region,
                'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', ''),
                'private_ip': instance.get('PrivateIpAddress', ''),
                'public_ip': instance.get('PublicIpAddress', ''),
                'private_dns': instance.get('PrivateDnsName', ''),
                'public_dns': instance.get('PublicDnsName', ''),
                'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else '',
                'platform': instance.get('Platform', 'Linux'),
                'architecture': instance.get('Architecture', ''),
                'vpc_id': instance.get('VpcId', ''),
                'subnet_id': instance.get('SubnetId', ''),
                'security_groups': instance.get('SecurityGroups', []),
                'key_name': instance.get('KeyName', ''),
                'ami_id': instance.get('ImageId', ''),
                'ami_info': ami_info,
                'root_device_type': instance.get('RootDeviceType', ''),
                'root_device_name': instance.get('RootDeviceName', ''),
                'virtualization_type': instance.get('VirtualizationType', ''),
                'tags': {tag['Key']: tag['Value'] for tag in tags},
                'monitoring': instance.get('Monitoring', {}).get('State', ''),
                'iam_instance_profile': instance.get('IamInstanceProfile', {}),
                'ebs_optimized': instance.get('EbsOptimized', False),
                'volumes': volumes,
                'network_interfaces': instance.get('NetworkInterfaces', []),
                'cpu_options': instance.get('CpuOptions', {}),
                'hibernation_options': instance.get('HibernationOptions', {}),
                'metadata_options': instance.get('MetadataOptions', {}),
                'enclave_options': instance.get('EnclaveOptions', {})
            }
    except ClientError as e:
        logger.error(f"Error fetching instance details: {e}")
        return None
    return None

def check_ssm_availability(instance_id, region):
    """Check if an instance is available for SSM commands"""
    try:
        ssm = get_ssm_client(region)
        if ssm is None:
            return {'available': False, 'reason': 'SSM client not available'}
        
        response = ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        
        if response['InstanceInformationList']:
            info = response['InstanceInformationList'][0]
            if info['PingStatus'] == 'Online':
                return {'available': True, 'platform': info.get('PlatformType', 'Unknown')}
            else:
                return {'available': False, 'reason': f"SSM Agent is not online (status: {info['PingStatus']})"}
        else:
            return {
                'available': False, 
                'reason': 'Instance not registered with SSM. Please ensure: 1) SSM Agent is installed and running, 2) Instance has an IAM role with AmazonSSMManagedInstanceCore policy attached'
            }
    except ClientError as e:
        return {'available': False, 'reason': str(e)}

def execute_ssm_command(instance_id, region, command, document_name='AWS-RunShellScript', wait_for_result=False):
    """Execute SSM command on an instance"""
    try:
        # First check if SSM is available for this instance
        ssm_check = check_ssm_availability(instance_id, region)
        if not ssm_check.get('available'):
            return {
                'success': False, 
                'error': ssm_check.get('reason', 'SSM not available'),
                'ssm_not_configured': True
            }
        
        ssm = get_ssm_client(region)
        if ssm is None:
            return {'success': False, 'error': 'SSM client not available'}
        
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName=document_name,
            Parameters={'commands': [command]},
            TimeoutSeconds=300
        )
        
        command_id = response['Command']['CommandId']
        
        if not wait_for_result:
            return {'success': True, 'command_id': command_id}
        
        # Wait for command to complete and get output
        import time
        max_wait = 120  # Maximum 2 minutes
        wait_interval = 3  # Check every 3 seconds
        elapsed = 0
        
        while elapsed < max_wait:
            time.sleep(wait_interval)
            elapsed += wait_interval
            
            try:
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                
                status = result['Status']
                
                if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                    return {
                        'success': status == 'Success',
                        'command_id': command_id,
                        'status': status,
                        'output': result.get('StandardOutputContent', ''),
                        'error_output': result.get('StandardErrorContent', ''),
                        'exit_code': result.get('ResponseCode', -1)
                    }
            except ClientError as e:
                if 'InvocationDoesNotExist' in str(e):
                    continue  # Command not yet registered, keep waiting
                raise
        
        return {
            'success': False,
            'command_id': command_id,
            'status': 'TimedOut',
            'error': 'Command timed out waiting for response'
        }
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = str(e)
        
        if 'InvalidInstanceId' in error_code or 'InvalidInstanceId' in error_msg:
            return {
                'success': False,
                'error': 'Instance not registered with SSM. Please ensure: 1) SSM Agent is installed and running, 2) Instance has an IAM role with AmazonSSMManagedInstanceCore policy attached',
                'ssm_not_configured': True
            }
        
        return {'success': False, 'error': error_msg}

def check_splunk_status(instance_id, region):
    """Check if Splunk is installed and running on an instance"""
    command = '''
    if command -v /opt/splunkforwarder/bin/splunk &> /dev/null; then
        SPLUNK_VERSION=$(/opt/splunkforwarder/bin/splunk version 2>/dev/null || echo "unknown")
        SPLUNK_STATUS=$(/opt/splunkforwarder/bin/splunk status 2>/dev/null || echo "not running")
        echo "installed:true"
        echo "version:$SPLUNK_VERSION"
        echo "status:$SPLUNK_STATUS"
    elif command -v /opt/splunk/bin/splunk &> /dev/null; then
        SPLUNK_VERSION=$(/opt/splunk/bin/splunk version 2>/dev/null || echo "unknown")
        SPLUNK_STATUS=$(/opt/splunk/bin/splunk status 2>/dev/null || echo "not running")
        echo "installed:true"
        echo "version:$SPLUNK_VERSION"
        echo "status:$SPLUNK_STATUS"
    else
        echo "installed:false"
    fi
    '''
    return execute_ssm_command(instance_id, region, command)

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html', regions=AWS_REGIONS)

@app.route('/splunk-dashboard')
def splunk_dashboard():
    """Splunk maintenance dashboard"""
    return render_template('splunk_dashboard.html', regions=AWS_REGIONS)

@app.route('/api/instances')
def api_get_instances():
    """API endpoint to get all instances"""
    regions = request.args.getlist('regions')
    search = request.args.get('search', '').lower()
    state_filter = request.args.get('state', '')
    quick = request.args.get('quick', 'false').lower() == 'true'
    
    if not regions:
        # Use quick regions for faster loading, or all regions if specified
        regions = QUICK_REGIONS if quick else None
    
    instances = get_all_instances(regions)
    
    # Apply search filter
    if search:
        instances = [i for i in instances if 
                    search in i['name'].lower() or 
                    search in i['instance_id'].lower() or 
                    search in i['instance_type'].lower()]
    
    # Apply state filter
    if state_filter:
        instances = [i for i in instances if i['state'] == state_filter]
    
    return jsonify({'instances': instances, 'count': len(instances)})

@app.route('/api/instance/<instance_id>')
def api_get_instance_details(instance_id):
    """API endpoint to get instance details"""
    region = request.args.get('region')
    if not region:
        return jsonify({'error': 'Region is required'}), 400
    
    details = get_instance_details(instance_id, region)
    if details:
        return jsonify(details)
    return jsonify({'error': 'Instance not found'}), 404

@app.route('/api/instance/<instance_id>/start', methods=['POST'])
def api_start_instance(instance_id):
    """Start an EC2 instance"""
    region = request.json.get('region')
    try:
        ec2 = get_ec2_client(region)
        ec2.start_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'message': f'Instance {instance_id} starting'})
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/instance/<instance_id>/stop', methods=['POST'])
def api_stop_instance(instance_id):
    """Stop an EC2 instance"""
    region = request.json.get('region')
    try:
        ec2 = get_ec2_client(region)
        ec2.stop_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'message': f'Instance {instance_id} stopping'})
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/instance/<instance_id>/reboot', methods=['POST'])
def api_reboot_instance(instance_id):
    """Reboot an EC2 instance"""
    region = request.json.get('region')
    try:
        ec2 = get_ec2_client(region)
        ec2.reboot_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'message': f'Instance {instance_id} rebooting'})
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/instance/<instance_id>/terminate', methods=['POST'])
def api_terminate_instance(instance_id):
    """Terminate an EC2 instance"""
    region = request.json.get('region')
    try:
        ec2 = get_ec2_client(region)
        ec2.terminate_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'message': f'Instance {instance_id} terminating'})
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Splunk API endpoints
@app.route('/api/splunk/status', methods=['POST'])
def api_splunk_status():
    """Check Splunk status on an instance"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    result = check_splunk_status(instance_id, region)
    return jsonify(result)

@app.route('/api/splunk/install', methods=['POST'])
def api_splunk_install():
    """Install Splunk on an instance with auto OS detection"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    splunk_version = data.get('version', '9.1.2')
    environment = data.get('environment', 'nonprod')  # 'prod', 'nonprod', or 'none'
    
    # Determine deployment server based on environment
    deployment_server = None
    deployment_host = None
    if environment == 'prod':
        deployment_server = 'splunk-prd-deployment.arlocloud.com:8089'
        deployment_host = 'splunk-prd-deployment.arlocloud.com'
    elif environment == 'nonprod':
        deployment_server = 'splunk-nprod-deployment.arlocloud.com:8089'
        deployment_host = 'splunk-nprod-deployment.arlocloud.com'
    
    # Deployment config section
    if deployment_server:
        deployment_config = f'''
    # Step 8: Create deploymentclient.conf
    echo "Step 8: Configuring deployment client for {environment}..."
    mkdir -p $SPLUNK_HOME/etc/system/local
    cat > $SPLUNK_HOME/etc/system/local/deploymentclient.conf << 'EOFCONFIG'
[target-broker:deploymentServer]
targetUri = {deployment_server}
EOFCONFIG
    
    chown splunkfwd:splunkfwd $SPLUNK_HOME/etc/system/local/deploymentclient.conf
    
    # Step 9: Test network connectivity to deployment server
    echo "Step 9: Testing network connectivity to deployment server..."
    nc -zv {deployment_host} 8089 2>&1 || echo "WARNING: Cannot connect to deployment server. Please verify network connectivity."
    
    # Step 10: Restart Splunk to apply configuration
    echo "Step 10: Restarting Splunk..."
    sudo -u splunkfwd $SPLUNK_HOME/bin/splunk restart
    
    echo ""
    echo "=== Splunk Universal Forwarder Installation Completed ==="
    echo "Deployment Server: {deployment_server}"
'''
    else:
        deployment_config = '''
    echo "Step 8: Skipping deployment client configuration (None selected)..."
    echo ""
    echo "=== Splunk Universal Forwarder Installation Completed ==="
    echo "Deployment Server: None (not configured)"
'''
    
    # Command with auto OS detection
    command = f'''
    echo "=== Splunk Universal Forwarder Installation ==="
    echo "Version: {splunk_version}"
    echo "Environment: {environment}"
    echo ""
    
    # Auto-detect OS type from /etc/os-release
    echo "Step 0: Detecting Operating System..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${{ID}}"
        OS_ID_LIKE="${{ID_LIKE:-}}"
        OS_VERSION="${{VERSION_ID}}"
        echo "Detected OS: ${{PRETTY_NAME:-$OS_ID}}"
    else
        OS_ID="unknown"
        OS_ID_LIKE=""
        echo "Warning: /etc/os-release not found, defaulting to TAR package"
    fi
    
    # Determine package type based on OS
    PKG_TYPE="tar"
    if [[ "$OS_ID" == "rhel" ]] || [[ "$OS_ID" == "centos" ]] || [[ "$OS_ID" == "fedora" ]] || [[ "$OS_ID" == "amzn" ]] || [[ "$OS_ID" == "ol" ]] || [[ "$OS_ID_LIKE" == *"rhel"* ]] || [[ "$OS_ID_LIKE" == *"fedora"* ]]; then
        PKG_TYPE="rpm"
        echo "Package type: RPM (Red Hat/CentOS/Amazon Linux/Fedora)"
    elif [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]] || [[ "$OS_ID_LIKE" == *"debian"* ]]; then
        PKG_TYPE="deb"
        echo "Package type: DEB (Debian/Ubuntu)"
    elif [[ "$OS_ID" == "sles" ]] || [[ "$OS_ID" == "opensuse"* ]]; then
        PKG_TYPE="rpm"
        echo "Package type: RPM (SUSE)"
    else
        echo "Package type: TAR (Generic Linux)"
    fi
    echo ""
    
    # Set SPLUNK_HOME
    export SPLUNK_HOME="/opt/splunkforwarder"
    
    # Step 1: Create the Splunk user and group
    echo "Step 1: Creating splunkfwd user and group..."
    groupadd splunkfwd 2>/dev/null || true
    useradd -m -g splunkfwd splunkfwd 2>/dev/null || true
    
    # Step 2: Create the SPLUNK_HOME directory
    echo "Step 2: Creating $SPLUNK_HOME directory..."
    mkdir -p $SPLUNK_HOME
    
    # Step 3 & 4: Download and install based on detected package type
    cd /tmp
    if [[ "$PKG_TYPE" == "rpm" ]]; then
        echo "Step 3: Downloading Splunk Universal Forwarder {splunk_version} (RPM)..."
        wget -q --show-progress -O splunkforwarder-{splunk_version}.rpm "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-x86_64.rpm" || curl -L -o splunkforwarder-{splunk_version}.rpm "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-x86_64.rpm"
        
        echo "Step 4: Installing RPM package..."
        chmod 644 splunkforwarder-{splunk_version}.rpm
        rpm -i --replacepkgs splunkforwarder-{splunk_version}.rpm 2>/dev/null || rpm -U splunkforwarder-{splunk_version}.rpm
        
    elif [[ "$PKG_TYPE" == "deb" ]]; then
        echo "Step 3: Downloading Splunk Universal Forwarder {splunk_version} (DEB)..."
        wget -q --show-progress -O splunkforwarder-{splunk_version}.deb "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-amd64.deb" || curl -L -o splunkforwarder-{splunk_version}.deb "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-amd64.deb"
        
        echo "Step 4: Installing DEB package..."
        dpkg -i splunkforwarder-{splunk_version}.deb
        
    else
        echo "Step 3: Downloading Splunk Universal Forwarder {splunk_version} (TAR)..."
        wget -q --show-progress -O splunkforwarder-{splunk_version}.tgz "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-x86_64.tgz" || curl -L -o splunkforwarder-{splunk_version}.tgz "https://download.splunk.com/products/universalforwarder/releases/{splunk_version}/linux/splunkforwarder-{splunk_version}-linux-x86_64.tgz"
        
        echo "Step 4: Extracting TAR package..."
        tar xzf splunkforwarder-{splunk_version}.tgz -C /opt
    fi
    
    # Step 5: Change ownership
    echo "Step 5: Setting ownership to splunkfwd:splunkfwd..."
    chown -R splunkfwd:splunkfwd $SPLUNK_HOME
    
    # Step 6: Start Splunk and accept license
    echo "Step 6: Starting Splunk and accepting license..."
    sudo -u splunkfwd $SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt
    
    # Step 7: Enable boot-start
    echo "Step 7: Enabling boot-start..."
    $SPLUNK_HOME/bin/splunk enable boot-start -user splunkfwd
    {deployment_config}
    $SPLUNK_HOME/bin/splunk version
    $SPLUNK_HOME/bin/splunk status
    '''
    
    result = execute_ssm_command(instance_id, region, command)
    return jsonify(result)

@app.route('/api/splunk/upgrade', methods=['POST'])
def api_splunk_upgrade():
    """Upgrade Splunk on an instance"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    new_version = data.get('version', '9.2.0')
    
    command = f'''
    # Stop Splunk
    /opt/splunkforwarder/bin/splunk stop || /opt/splunk/bin/splunk stop
    
    # Backup current config
    cp -r /opt/splunkforwarder/etc /opt/splunkforwarder/etc.backup 2>/dev/null || cp -r /opt/splunk/etc /opt/splunk/etc.backup
    
    # Download new version
    cd /tmp
    wget -O splunkforwarder-new.tgz "https://download.splunk.com/products/universalforwarder/releases/{new_version}/linux/splunkforwarder-{new_version}-linux-2.6-x86_64.tgz"
    
    # Extract and upgrade
    tar -xzf splunkforwarder-new.tgz -C /opt --overwrite
    
    # Start with upgrade flag
    /opt/splunkforwarder/bin/splunk start --accept-license --no-prompt --answer-yes
    
    echo "Splunk upgrade completed to version {new_version}"
    '''
    
    result = execute_ssm_command(instance_id, region, command)
    return jsonify(result)

@app.route('/api/splunk/remove', methods=['POST'])
def api_splunk_remove():
    """Remove Splunk from an instance"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    command = '''
    # Stop Splunk
    /opt/splunkforwarder/bin/splunk stop 2>/dev/null || true
    /opt/splunk/bin/splunk stop 2>/dev/null || true
    
    # Disable boot-start
    /opt/splunkforwarder/bin/splunk disable boot-start 2>/dev/null || true
    /opt/splunk/bin/splunk disable boot-start 2>/dev/null || true
    
    # Remove installation
    rm -rf /opt/splunkforwarder
    rm -rf /opt/splunk
    
    # Remove splunk user
    userdel splunk 2>/dev/null || true
    
    echo "Splunk has been removed"
    '''
    
    result = execute_ssm_command(instance_id, region, command)
    return jsonify(result)

@app.route('/api/splunk/remove-duplicate-config', methods=['POST'])
def api_splunk_remove_duplicate_config():
    """Remove duplicate Splunk configurations using clone-prep-clear-config"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    command = '''
    echo "Stopping Splunk..."
    /opt/splunkforwarder/bin/splunk stop
    
    echo "Waiting 5 seconds..."
    sleep 5
    
    echo "Clearing duplicate configurations..."
    /opt/splunkforwarder/bin/splunk clone-prep-clear-config
    
    echo "Waiting 5 seconds..."
    sleep 5
    
    echo "Starting Splunk..."
    /opt/splunkforwarder/bin/splunk start
    
    echo "Duplicate configurations have been cleared successfully"
    '''
    
    result = execute_ssm_command(instance_id, region, command)
    return jsonify(result)

@app.route('/api/regions')
def api_get_regions():
    """Get list of AWS regions"""
    return jsonify({'regions': AWS_REGIONS})

@app.route('/api/ssm/command-status', methods=['POST'])
def api_get_command_status():
    """Get the status and output of an SSM command"""
    data = request.json
    command_id = data.get('command_id')
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    try:
        ssm = get_ssm_client(region)
        if ssm is None:
            return jsonify({'success': False, 'error': 'SSM client not available'})
        
        result = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        
        status = result['Status']
        
        return jsonify({
            'success': True,
            'status': status,
            'in_progress': status in ['Pending', 'InProgress', 'Delayed'],
            'completed': status in ['Success', 'Failed', 'Cancelled', 'TimedOut'],
            'output': result.get('StandardOutputContent', ''),
            'error_output': result.get('StandardErrorContent', ''),
            'exit_code': result.get('ResponseCode', -1)
        })
    except ClientError as e:
        if 'InvocationDoesNotExist' in str(e):
            return jsonify({
                'success': True,
                'status': 'Pending',
                'in_progress': True,
                'completed': False,
                'output': '',
                'error_output': ''
            })
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ssm/setup', methods=['POST'])
def api_setup_ssm():
    """Set up SSM Agent on an instance - NO RESTART, NO SSH"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    # First ensure IAM role is attached (no restart needed)
    iam_result = ensure_iam_role(instance_id, region)
    if not iam_result.get('success'):
        return jsonify({
            'success': False,
            'step': 'iam_role',
            'error': iam_result.get('error', 'Failed to attach IAM role')
        })
    
    # Wait a moment for IAM role to propagate
    time.sleep(10)
    
    # Check if SSM becomes available (agent may already be installed)
    ssm_check = check_ssm_availability(instance_id, region)
    
    if ssm_check.get('available'):
        return jsonify({
            'success': True,
            'message': 'SSM is now available. IAM role was attached and SSM Agent was already installed.',
            'ready': True
        })
    
    # SSM not available - provide manual instructions
    ssm_info = setup_ssm_agent(instance_id, region)
    return jsonify({
        'success': False,
        'requires_manual': True,
        'error': 'SSM Agent needs to be installed manually on this instance.',
        'manual_instructions': ssm_info.get('manual_instructions', ''),
        'instance_info': ssm_info.get('instance_info', {})
    })

@app.route('/api/ssm/wait-registration', methods=['POST'])
def api_wait_ssm_registration():
    """Wait for SSM registration to complete"""
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    max_wait = data.get('max_wait', 180)
    
    registered = wait_for_ssm_registration(instance_id, region, max_wait)
    
    return jsonify({
        'success': registered,
        'registered': registered,
        'message': 'SSM Agent registered successfully' if registered else 'SSM Agent registration timed out'
    })

@app.route('/api/preflight-check', methods=['POST'])
def api_preflight_check():
    """
    Run preflight checks before Splunk installation.
    Checks: IAM role, SSM availability, instance state
    """
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    checks = {
        'instance_running': False,
        'iam_role_attached': False,
        'ssm_available': False,
        'ready_for_install': False
    }
    issues = []
    
    try:
        ec2 = get_ec2_client(region)
        
        # Check instance state
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        instance_state = instance['State']['Name']
        
        checks['instance_running'] = instance_state == 'running'
        if not checks['instance_running']:
            issues.append(f"Instance is {instance_state}, must be running")
        
        # Check IAM role
        if instance.get('IamInstanceProfile'):
            checks['iam_role_attached'] = True
        else:
            issues.append("No IAM role attached")
        
        # Check SSM availability
        ssm_check = check_ssm_availability(instance_id, region)
        checks['ssm_available'] = ssm_check.get('available', False)
        if not checks['ssm_available']:
            issues.append(ssm_check.get('reason', 'SSM not available'))
        
        # Determine if ready
        checks['ready_for_install'] = all([
            checks['instance_running'],
            checks['iam_role_attached'],
            checks['ssm_available']
        ])
        
        return jsonify({
            'success': True,
            'checks': checks,
            'issues': issues,
            'ready': checks['ready_for_install']
        })
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'checks': checks,
            'issues': issues
        })

@app.route('/api/auto-setup', methods=['POST'])
def api_auto_setup():
    """
    Automatically set up all prerequisites for Splunk installation.
    This handles IAM role and waits for SSM registration.
    NO RESTART, NO SSH - only IAM role attachment and waiting.
    """
    data = request.json
    instance_id = data.get('instance_id')
    region = data.get('region')
    
    result = {
        'steps': [],
        'success': False,
        'ready': False
    }
    
    try:
        # Step 1: Check current state
        result['steps'].append({'name': 'Checking instance state', 'status': 'running'})
        
        ec2 = get_ec2_client(region)
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        result['steps'][-1]['status'] = 'success'
        result['steps'][-1]['detail'] = f"Instance state: {instance['State']['Name']} (no restart will be performed)"
        
        # Step 2: Ensure IAM role (NO RESTART REQUIRED)
        result['steps'].append({'name': 'Attaching IAM role with SSM permissions', 'status': 'running'})
        iam_result = ensure_iam_role(instance_id, region)
        
        if iam_result.get('success'):
            result['steps'][-1]['status'] = 'success'
            result['steps'][-1]['detail'] = iam_result.get('message', 'IAM role attached (no restart)')
        else:
            result['steps'][-1]['status'] = 'error'
            result['steps'][-1]['detail'] = iam_result.get('error', 'Failed to attach IAM role')
            return jsonify(result)
        
        # Step 3: Wait for SSM to become available
        # SSM Agent may already be installed, just needed the IAM role
        result['steps'].append({'name': 'Waiting for SSM Agent to register (30s)', 'status': 'running'})
        
        # Wait and check multiple times
        for i in range(3):
            time.sleep(10)
            ssm_check = check_ssm_availability(instance_id, region)
            if ssm_check.get('available'):
                result['steps'][-1]['status'] = 'success'
                result['steps'][-1]['detail'] = 'SSM Agent registered successfully!'
                result['success'] = True
                result['ready'] = True
                return jsonify(result)
        
        # SSM still not available - need manual installation
        result['steps'][-1]['status'] = 'warning'
        result['steps'][-1]['detail'] = 'SSM Agent not detected - manual installation required'
        
        # Get instance info for manual instructions
        ssm_info = setup_ssm_agent(instance_id, region)
        
        result['requires_manual'] = True
        result['manual_instructions'] = ssm_info.get('manual_instructions', '')
        result['instance_info'] = ssm_info.get('instance_info', {})
        result['error'] = 'SSM Agent is not installed on this instance. Please install it manually (no restart required).'
        
        return jsonify(result)
        
    except Exception as e:
        result['steps'].append({'name': 'Error', 'status': 'error', 'detail': str(e)})
        return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

