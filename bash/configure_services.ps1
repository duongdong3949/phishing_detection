$ErrorActionPreference = "Continue"

$COSMOS_MONGO_URI = 'mongodb+srv://dong075:Password%40666@zevuqxrbyni.global.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000'

$RG = "Crawlers"
$DOCKER_USER = "duongdong3949"
$SUFFIX = "duong3949"

Write-Host "=== BAT DAU CAU HINH SERVICES ===" -ForegroundColor Cyan
Write-Host "✓ Su dung Azure Cosmos DB for MongoDB." -ForegroundColor Green
Write-Host "URI: $COSMOS_MONGO_URI" -ForegroundColor DarkGray

Write-Host ""
Write-Host "--- 2. Configuring App Services ---" -ForegroundColor Yellow

function Configure-WebApp {
    param (
        [string]$AppName,
        [string]$ImageName,
        [string]$DbName,
        [string]$ColName
    )

    Write-Host "Configuring $AppName..." -NoNewline
    
    $appSettings = @{
        "MONGO_URI"       = $COSMOS_MONGO_URI
        "DB_NAME"         = $DbName
        "COLLECTION_NAME" = $ColName
        "WEBSITES_PORT"   = "8000"
    }

    $JsonPath = ".\temp_config.json"
    $appSettings | ConvertTo-Json -Depth 2 | Set-Content -Path $JsonPath -Encoding UTF8

    az webapp config appsettings set -g $RG -n $AppName --settings "@$JsonPath" --output none 2>$null

    az webapp config container set -g $RG -n $AppName `
        --container-image-name "$DOCKER_USER/$ImageName`:latest" `
        --container-registry-url "https://index.docker.io/v1" --output none 2>$null

    if (Test-Path $JsonPath) { Remove-Item $JsonPath }
    
    az webapp restart -g $RG -n $AppName --output none 2>$null
    Write-Host " [OK] Configured & Restarted" -ForegroundColor Green
}

$LOCS = @("japaneast", "eastasia", "southeastasia", "centralindia")
$i = 0

foreach ($loc in $LOCS) {
    $i++
    $dbName = "distributed_db_$i"
    $colName = "raw_distributed_data_$i"
    $appName = "distributed-crawler-$loc-$SUFFIX"
    
    Configure-WebApp -AppName $appName -ImageName "distributed_crawler" -DbName $dbName -ColName $colName
}

$OtherServices = @{
    "certificate_crawler"      = @("certificate_db",      "raw_certificate_data")
    "http_header_crawler"      = @("http_header_db",      "raw_http_header_data") 
    "http_redirection_crawler" = @("http_redirection_db", "raw_redirection_data") 
    "url_lexical_crawler"      = @("url_lexical_db",      "raw_url_lexical_data") 
    "whois_crawler"            = @("whois_db",            "raw_whois_data")
}

foreach ($key in $OtherServices.Keys) {
    $appNameClean = $key -replace "_", "-"
    $appName = "$appNameClean-$SUFFIX"
    $val = $OtherServices[$key]
    Configure-WebApp -AppName $appName -ImageName $key -DbName $val[0] -ColName $val[1]
}

Write-Host "✓ App Services configurations sent." -ForegroundColor Cyan


Write-Host ""
Write-Host "--- 3. Configuring VM Crawlers (RunShellScript inside Linux) ---" -ForegroundColor Yellow

function Configure-VM {
    param (
        [string]$VmPrefix,
        [string]$DbName,
        [string]$ColName
    )
    
    $VmNameClean = $VmPrefix -replace "_", "-"
    $VmName = "$VmNameClean-vm"
    $ImageName = $VmPrefix

    Write-Host "Configuring VM: $VmName..." -NoNewline

    $EnvContent = "MONGO_URI=$COSMOS_MONGO_URI`nDB_NAME=$DbName`nCOLLECTION_NAME=$ColName"
    
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($EnvContent)
    $EnvBase64 = [Convert]::ToBase64String($Bytes)

    $LocalScriptPath = "$PWD\temp_deploy.sh"
    
    $BashContent = @"
#!/bin/bash
set -e

echo "--- 1. CONFIGURING ENV ---"
sudo mkdir -p /app
sudo chmod 777 /app
echo "$EnvBase64" | base64 --decode > /app/.env

if [ ! -f /app/.env ]; then
    echo "❌ ERROR: Failed to create /app/.env"
    exit 1
else
    echo "✅ Created /app/.env"
fi

echo "--- 2. DOCKER SETUP ---"
sudo docker stop $ImageName 2>/dev/null || true
sudo docker rm $ImageName 2>/dev/null || true

sudo docker pull ${DOCKER_USER}/${ImageName}:latest

echo "--- 3. RUNNING CONTAINER ---"
sudo docker run -d \
  --name $ImageName \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --env-file /app/.env \
  ${DOCKER_USER}/${ImageName}:latest

echo "--- 4. HEALTH CHECK ---"
sleep 5
if [ `$(sudo docker ps -q -f name=$ImageName | wc -l) -eq 0 ]; then
    echo "❌ ERROR: Container crashed!"
    echo "=== LOGS ==="
    sudo docker logs $ImageName
    exit 1
else
    echo "✅ SUCCESS: Container is running."
    sudo docker ps -f name=$ImageName
fi
"@
    
    try {
        $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::WriteAllText($LocalScriptPath, $BashContent, $Utf8NoBomEncoding)
    }
    catch {
        Write-Error "Error creating temp file: $_"
        return
    }

    try {
        $result = az vm run-command invoke -g $RG -n $VmName --command-id RunShellScript --scripts "@$LocalScriptPath" --output json
        
        if ($result) {
            $jsonResult = $result | ConvertFrom-Json
            $msg = $jsonResult.value[0].message
            
            Write-Host ""
            Write-Host "---------------- VM LOGS ($VmName) ----------------" -ForegroundColor Cyan
            Write-Host $msg
            Write-Host "---------------------------------------------------" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host " [ERROR] Azure Command Failed: $_" -ForegroundColor Red
    }

    if (Test-Path $LocalScriptPath) { Remove-Item $LocalScriptPath }
}

Configure-VM -VmPrefix "network_crawler"       -DbName "network_db"       -ColName "raw_network_data"      
Configure-VM -VmPrefix "server_status_crawler" -DbName "server_status_db" -ColName "raw_server_status_data" 

Write-Host ""
Write-Host "--- 4. Configuring NSG Rules & Getting IPs ---" -ForegroundColor Yellow

$VmPrefixes = @("network_crawler", "server_status_crawler")
foreach ($prefix in $VmPrefixes) {
    $cleanName = $prefix -replace "_", "-"
    $vmName = "$cleanName-vm"
    $nsgName = "$vmName`NSG" 
    
    Write-Host "Opening Port 8000 for $vmName..." -NoNewline
    az network nsg rule create -g $RG --nsg-name $nsgName -n "Allow-8000" --priority 1010 --destination-port-ranges 8000 --access Allow --protocol Tcp --direction Inbound --output none 2>$null
    Write-Host " [OK]" -ForegroundColor Green
}

$NET_IP = az vm show -d -g $RG -n "network-crawler-vm" --query publicIps -o tsv 2>$null
$SRV_IP = az vm show -d -g $RG -n "server-status-crawler-vm" --query publicIps -o tsv 2>$null

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "   CAU HINH HOAN TAT!" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "Connection String: Da inject qua JSON File (Safe Mode)."
Write-Host "VM Public Endpoints (Port 8000):"
Write-Host "  - Network Crawler:      http://$($NET_IP):8000/extract"
Write-Host "  - Server Status:        http://$($SRV_IP):8000/extract"
Write-Host "=========================================================" -ForegroundColor Cyan