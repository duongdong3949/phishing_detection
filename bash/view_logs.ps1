$RESOURCE_GROUP = "Crawlers"
$APP_SUFFIX = "duong3949"
$ADMIN_USER = "sinhvien_admin"

function Show-WebAppLogs {
    param (
        [string]$AppName
    )
    
    $FullName = "$AppName-$APP_SUFFIX"
    
    Write-Host "--- Processing: $FullName ---" -ForegroundColor Cyan
    
    Write-Host "1. Enabling Docker logs..." -NoNewline
    az webapp log config -g $RESOURCE_GROUP -n $FullName --docker-container-logging filesystem --output none 2>$null
    Write-Host " [DONE]" -ForegroundColor Green
    
    Write-Host "2. Restarting App to capture startup errors..." -NoNewline
    az webapp restart -g $RESOURCE_GROUP -n $FullName --output none 2>$null
    Write-Host " [DONE]" -ForegroundColor Green
    
    Write-Host "3. Waiting 5s for boot up..."
    Start-Sleep -Seconds 5
    
    Write-Host "4. Streaming Logs (Ctrl + C to exit)..." -ForegroundColor Yellow
    Write-Host "----------------------------------------"
    az webapp log tail -g $RESOURCE_GROUP -n $FullName
}

function Show-VMLogs {
    param (
        [string]$VmName,
        [string]$ContainerName
    )
    
    Write-Host "--- Fetching IP for $VmName ---" -ForegroundColor Cyan
    
    $IP = az vm show -d -g $RESOURCE_GROUP -n $VmName --query publicIps -o tsv 2>$null
    
    if ([string]::IsNullOrWhiteSpace($IP)) {
        Write-Host "❌ Error: Could not find IP for VM: $VmName. (VM co the dang tat?)" -ForegroundColor Red
        return
    }
    
    Write-Host "Connecting to $IP ($ADMIN_USER)..." -ForegroundColor Yellow
    Write-Host "💡 Tip: Nhap password neu duoc hoi." -ForegroundColor Gray
    Write-Host "💡 Nhan Ctrl + C de thoat xem log." -ForegroundColor Gray
    Write-Host "-----------------------------------------------------"
    
    ssh -t "$ADMIN_USER@$IP" "sudo docker logs -f --tail 100 $ContainerName"
}

while ($true) {
    Clear-Host 
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "       LOG VIEWER - $RESOURCE_GROUP       " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    Write-Host "--- App Services (Auto Restart & Stream) ---" -ForegroundColor Yellow
    Write-Host "1.  distributed-crawler-japaneast"
    Write-Host "2.  distributed-crawler-eastasia"
    Write-Host "3.  distributed-crawler-southeastasia"
    Write-Host "4.  distributed-crawler-centralindia"
    Write-Host "5.  certificate-crawler"
    Write-Host "6.  http-header-crawler"
    Write-Host "7.  http-redirection-crawler"
    Write-Host "8.  url-lexical-crawler"
    Write-Host "9.  whois-crawler"
    Write-Host ""
    Write-Host "--- Virtual Machines (Real-time via SSH) ---" -ForegroundColor Yellow
    Write-Host "10. network-crawler-vm (network_crawler)"
    Write-Host "11. server-status-crawler-vm (server_status_crawler)"
    Write-Host ""
    Write-Host "0.  Exit"
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $choice = Read-Host "Select service (0-11)"

    switch ($choice) {
        "1" { Show-WebAppLogs -AppName "distributed-crawler-japaneast" }
        "2" { Show-WebAppLogs -AppName "distributed-crawler-eastasia" }
        "3" { Show-WebAppLogs -AppName "distributed-crawler-southeastasia" }
        "4" { Show-WebAppLogs -AppName "distributed-crawler-centralindia" }
        
        "5" { Show-WebAppLogs -AppName "certificate-crawler" }
        "6" { Show-WebAppLogs -AppName "http-header-crawler" }
        "7" { Show-WebAppLogs -AppName "http-redirection-crawler" }
        "8" { Show-WebAppLogs -AppName "url-lexical-crawler" }
        "9" { Show-WebAppLogs -AppName "whois-crawler" }
        
        "10" { Show-VMLogs -VmName "network-crawler-vm" -ContainerName "network_crawler" }
        "11" { Show-VMLogs -VmName "server-status-crawler-vm" -ContainerName "server_status_crawler" }
        
        "0" { Write-Host "Bye!"; exit }
        Default { Write-Host "Lua chon khong hop le!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue..."
}