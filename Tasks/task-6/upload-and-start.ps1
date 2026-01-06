# Upload and Start Script for EC2 Inventory Portal
# Run this after the EC2 instance is ready

param(
    [Parameter(Mandatory=$true)]
    [string]$PublicIP,
    
    [string]$KeyFile = "ec2-inventory-key.pem"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Uploading Application to EC2 Instance" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "Target: ec2-user@$PublicIP" -ForegroundColor Yellow
Write-Host "Key File: $KeyFile" -ForegroundColor Yellow
Write-Host ""

# Check if key file exists
if (-not (Test-Path $KeyFile)) {
    Write-Host "Error: Key file '$KeyFile' not found!" -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] Uploading application files..." -ForegroundColor Yellow

# Upload files using SCP
$filesToUpload = @(
    "app.py",
    "requirements.txt"
)

foreach ($file in $filesToUpload) {
    $filePath = Join-Path $ScriptDir $file
    if (Test-Path $filePath) {
        Write-Host "  Uploading $file..." -ForegroundColor Gray
        scp -i $KeyFile -o StrictHostKeyChecking=no "$filePath" "ec2-user@${PublicIP}:/tmp/"
    } else {
        Write-Host "  Warning: $file not found!" -ForegroundColor Yellow
    }
}

# Upload templates directory
$templatesDir = Join-Path $ScriptDir "templates"
if (Test-Path $templatesDir) {
    Write-Host "  Uploading templates directory..." -ForegroundColor Gray
    scp -i $KeyFile -o StrictHostKeyChecking=no -r "$templatesDir" "ec2-user@${PublicIP}:/tmp/"
}

Write-Host ""
Write-Host "[2/3] Moving files and installing dependencies..." -ForegroundColor Yellow

# SSH commands to set up the application
$sshCommands = @"
sudo mv /tmp/app.py /opt/ec2-inventory/
sudo mv /tmp/requirements.txt /opt/ec2-inventory/
sudo rm -rf /opt/ec2-inventory/templates
sudo mv /tmp/templates /opt/ec2-inventory/
cd /opt/ec2-inventory
sudo /opt/ec2-inventory/venv/bin/pip install -r requirements.txt
"@

ssh -i $KeyFile -o StrictHostKeyChecking=no "ec2-user@$PublicIP" $sshCommands

Write-Host ""
Write-Host "[3/3] Starting the application..." -ForegroundColor Yellow

ssh -i $KeyFile -o StrictHostKeyChecking=no "ec2-user@$PublicIP" "sudo systemctl start ec2-inventory && sudo systemctl status ec2-inventory"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Application Deployed Successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access your portal at:" -ForegroundColor Yellow
Write-Host "  http://${PublicIP}:5000" -ForegroundColor Green
Write-Host ""
Write-Host "Splunk Dashboard:" -ForegroundColor Yellow
Write-Host "  http://${PublicIP}:5000/splunk-dashboard" -ForegroundColor Green
Write-Host ""



