$ErrorActionPreference = "Continue"

$ErrorActionPreference = "Continue"

# Load .env file from parent directory
$EnvPath = Join-Path $PSScriptRoot "..\.env"
if (Test-Path $EnvPath) {
    Get-Content $EnvPath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $name, $value = $line -split "=", 2
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

$RESOURCE_GROUP = "Crawlers"
$LOCATION = "eastasia"

$ADMIN_USER = $env:ADMIN_USER
$ADMIN_PASS = $env:ADMIN_PASS

$DOCKER_USER = $env:DOCKER_USER
$APP_SUFFIX = $env:APP_SUFFIX

$LOCATIONS = @("japaneast", "eastasia", "southeastasia", "centralindia")

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "=== TẠO COMPUTE INFRASTRUCTURE (GỌN GÀNG) ===" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "--- 1. Setup Distributed Crawler (4 Regions) ---" -ForegroundColor Yellow

foreach ($LOC in $LOCATIONS) {
    $PLAN_NAME = "plan-distributed-crawler-$LOC"
    $APP_NAME = "distributed-crawler-$LOC-$APP_SUFFIX"
    
    Write-Host "[$LOC] Creating Plan: $PLAN_NAME..." -NoNewline
    az appservice plan create --name $PLAN_NAME --resource-group $RESOURCE_GROUP --sku F1 --is-linux --location $LOC --output none 2>$null
    Write-Host " [OK]" -ForegroundColor Green
    
    Write-Host "[$LOC] Creating App: $APP_NAME..." -NoNewline
    az webapp create --resource-group $RESOURCE_GROUP --plan $PLAN_NAME --name $APP_NAME --container-image-name "$DOCKER_USER/distributed_crawler:latest" --output none 2>$null
    Write-Host " [OK]" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- 2. Setup Other Services (5 Crawlers) ---" -ForegroundColor Yellow

$OTHER_SERVICES = @("certificate_crawler", "http_header_crawler", "http_redirection_crawler", "url_lexical_crawler", "whois_crawler")
$LOC = "eastasia"

foreach ($SERVICE in $OTHER_SERVICES) {
    $SERVICE_NAME_CLEAN = $SERVICE -replace "_", "-"
    $APP_NAME = "$SERVICE_NAME_CLEAN-$APP_SUFFIX"
    $PLAN_NAME = "plan-$SERVICE_NAME_CLEAN-$LOC"
    
    Write-Host "Creating: $APP_NAME..." -NoNewline
    
    az appservice plan create --name $PLAN_NAME --resource-group $RESOURCE_GROUP --sku F1 --is-linux --location $LOC --output none 2>$null
    
    az webapp create --resource-group $RESOURCE_GROUP --plan $PLAN_NAME --name $APP_NAME --container-image-name "$DOCKER_USER/$SERVICE`:latest" --output none 2>$null
    
    Write-Host " [OK]" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- 3. Setup Network & Server Status (VMs) ---" -ForegroundColor Yellow

$VM_SERVICES = @("network_crawler", "server_status_crawler")
$LOC = "southeastasia"

foreach ($SERVICE in $VM_SERVICES) {
    $SERVICE_NAME_CLEAN = $SERVICE -replace "_", "-"
    $VM_NAME = "$SERVICE_NAME_CLEAN-vm"
    
    Write-Host "Creating VM: $VM_NAME (co the mat vai phut)..." -NoNewline
    
    az vm create `
        --resource-group $RESOURCE_GROUP `
        --name $VM_NAME `
        --location $LOC `
        --size "Standard_B1s" `
        --image "Ubuntu2204" `
        --admin-username $ADMIN_USER `
        --admin-password $ADMIN_PASS `
        --nsg-rule SSH `
        --output none 2>$null
        
    Write-Host " [OK]" -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "=== HOAN TAT TAO COMPUTE RESOURCES! ===" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Da tao xong ha tang. Tiep theo hay chay file configure_services.ps1" -ForegroundColor White
Write-Host "============================================="