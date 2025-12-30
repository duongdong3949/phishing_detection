$ErrorActionPreference = "Stop"

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

$COSMOS_MONGO_URI = $env:MONGO_URI

$FIELD_TO_INDEX = "url" 

Write-Host "=== BAT DAU TAO INDEX CHO TRUONG: '$FIELD_TO_INDEX' ===" -ForegroundColor Cyan

function Create-Index {
    param (
        [string]$DbName,
        [string]$ColName
    )
    
    Write-Host "Processing: $DbName.$ColName..." -NoNewline
    
    $JsScript = @"
        try {
            var db = connect('$COSMOS_MONGO_URI').getSiblingDB('$DbName');
            var col = db.getCollection('$ColName');
            var result = col.createIndex({ '$FIELD_TO_INDEX': 1 });
            print(' [OK] Result: ' + JSON.stringify(result));
        } catch (e) {
            print(' [ERROR] ' + e);
            quit(1);
        }
"@

    try {
        $JsScript | docker run --rm -i mongo:latest mongosh --nodb --quiet
    }
    catch {
        Write-Host " [FAIL] Could not run Docker command." -ForegroundColor Red
    }
}

for ($i = 1; $i -le 4; $i++) {
    Create-Index -DbName "distributed_db_$i" -ColName "raw_distributed_data_$i"
}

$OtherServices = @{
    "certificate_db"      = "raw_certificate_data"
    "http_header_db"      = "raw_http_headers"
    "http_redirection_db" = "raw_redirections"
    "url_lexical_db"      = "raw_url_lexical"
    "whois_db"            = "raw_whois_data"
    "network_db"          = "raw_network_traffic"
    "server_status_db"    = "raw_server_scans"
}

foreach ($db in $OtherServices.Keys) {
    Create-Index -DbName $db -ColName $OtherServices[$db]
}

Write-Host ""
Write-Host "✅ Đã tạo Index xong cho toàn bộ Collection!" -ForegroundColor Cyan