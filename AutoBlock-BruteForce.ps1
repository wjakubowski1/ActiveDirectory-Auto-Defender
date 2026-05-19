# Active Directory SOAR: Automated Brute-Force Defender
# Monitors Event ID 4625 and blocks malicious IPs via Windows Firewall

$EventID = 4625
$Threshold = 5

Write-Host "[*] Initializing Active Directory Defender..." -ForegroundColor Cyan
Write-Host "[*] Monitoring Security Logs for Event ID $EventID (Failed Logons)" -ForegroundColor Cyan
Write-Host "------------------------------------------------------" -ForegroundColor Gray

# Retrieve the latest failed logon events
$Events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$EventID} -MaxEvents 100 -ErrorAction SilentlyContinue

if ($Events) {
    Write-Host "[!] Analyzing recent failed authentication attempts..." -ForegroundColor Yellow
    
    # Process events and extract attacker IP addresses (Index 19 in Event Properties)
    $Attackers = $Events | ForEach-Object { $_.Properties[19].Value } | Group-Object | Where-Object { $_.Count -ge $Threshold }
    
    foreach ($Attacker in $Attackers) {
        $MaliciousIP = $Attacker.Name
        $RuleName = "SOC-FIREWALL-BLOCK-$MaliciousIP"
        
        # Check if a blocking rule already exists for this IP
        $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if (-not $ExistingRule) {
            Write-Host "[+] THREAT DETECTED: IP $MaliciousIP exceeded threshold ($($Attacker.Count) attempts)." -ForegroundColor Red
            Write-Host "[+] Mitigating threat: Creating inbound block rule..." -ForegroundColor Yellow
            
            New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $MaliciousIP | Out-Null
            
            Write-Host "[+] SUCCESS: IP $MaliciousIP has been isolated from the network." -ForegroundColor Green
        }
    }
} else {
    Write-Host "[*] Environment secure. No brute-force attempts detected." -ForegroundColor Green
}

Write-Host "------------------------------------------------------" -ForegroundColor Gray
