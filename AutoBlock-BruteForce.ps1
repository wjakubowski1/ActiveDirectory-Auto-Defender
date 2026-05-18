$ErrorLimit = 5

Write-Host "Scanning security logs (Event ID 4625)" -ForegroundColor Cyan

$Logs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue

$AdressIP = @()

foreach ($Log in $Logs) {

    $IP = $Log.Properties[19].Value

    if($IP -ne "-" -and $IP -ne "::1" -and $IP -ne "127.0.0.1") {
    
        $AdressIP += $IP

    }

}

$Attacker = $AdressIP | Group-Object | Where-Object { $_.Count -ge $ErrorLimit }

foreach ($Attack in $Attacker) {

    $BadIP = $Attack.Name
    $RuleName = "SOC-FIREWALL-BLOCK-$BadIP"

    $Exists = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

    if (-not $Exists) {
    
        Write-Host "WARNING: Brute Force attack detected [IP: $BadIP] - [Attempts: $($Attack.Count)]" -ForegroundColor Red
        Write-Host "Running Firewall..." -ForegroundColor Yellow

        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $BadIP | Out-Null

        Write-Host "IP Adress $BadIP has been successfully blocked" -ForegroundColor Green

    } else {
    
        Write-Host "IP $BadIP is already blocked" -ForegroundColor Gray
    
    }

}

Write-Host "Scanning ended" -ForegroundColor Cyan
