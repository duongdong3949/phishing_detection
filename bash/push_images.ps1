$ErrorActionPreference = "Stop"

$DOCKER_USER = "duongdong3949"

Write-Host "--- Tagging and Pushing Images for user: $DOCKER_USER ---" -ForegroundColor Cyan

Write-Host "Processing Certificate Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-certificate:latest "$DOCKER_USER/certificate_crawler:latest"
docker push "$DOCKER_USER/certificate_crawler:latest"

Write-Host "Processing Distributed Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-distributed:latest "$DOCKER_USER/distributed_crawler:latest"
docker push "$DOCKER_USER/distributed_crawler:latest"

Write-Host "Processing HTTP Header Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-http_header:latest "$DOCKER_USER/http_header_crawler:latest"
docker push "$DOCKER_USER/http_header_crawler:latest"

Write-Host "Processing HTTP Redirection Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-http_redirection:latest "$DOCKER_USER/http_redirection_crawler:latest"
docker push "$DOCKER_USER/http_redirection_crawler:latest"

Write-Host "Processing Network Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-network:latest "$DOCKER_USER/network_crawler:latest"
docker push "$DOCKER_USER/network_crawler:latest"

Write-Host "Processing Server Status Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-server_status:latest "$DOCKER_USER/server_status_crawler:latest"
docker push "$DOCKER_USER/server_status_crawler:latest"

Write-Host "Processing URL Lexical Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-url_lexical:latest "$DOCKER_USER/url_lexical_crawler:latest"
docker push "$DOCKER_USER/url_lexical_crawler:latest"

Write-Host "Processing WHOIS Crawler..." -ForegroundColor Yellow
docker tag phishing_detection-whois:latest "$DOCKER_USER/whois_crawler:latest"
docker push "$DOCKER_USER/whois_crawler:latest"

Write-Host "--- All images processed! ---" -ForegroundColor Cyan