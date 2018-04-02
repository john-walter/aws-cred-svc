param([String]$adminTasks="F")
$Error=""
Clear-Host
if ($adminTasks -eq "F") {
	$arguments = "& '" + $MyInvocation.MyCommand.Definition + "' -adminTasks T"
	Start-Process powershell -Verb runAs -ArgumentList $arguments -Wait
	if (-Not $Error) {
		Start-Process -FilePath .\bin\aws-cred-svc-windows.exe -Wait -NoNewWindow
	} else {
		Write-Output "You must have administrator privileges to set up this service"
        pause
	}
} else {
    $defaultInterface = $(Get-WmiObject -Class Win32_IP4RouteTable | Where-Object { $_.Destination -eq "0.0.0.0" -and $_.Mask -eq "0.0.0.0" } | Select -first 1 InterfaceIndex)
    New-NetIPAddress -InterfaceIndex $defaultInterface.InterfaceIndex -IPAddress 169.254.169.254 -PrefixLength 32 -SkipAsSource $true -ErrorAction Ignore
    netsh advfirewall firewall delete rule name="aws-cred-svc"
    netsh advfirewall firewall add rule name="aws-cred-svc" localip=169.254.169.254 localport=80,12319 remoteip=127.0.0.1  protocol=tcp dir=in enable=yes action=allow profile=Private
    netsh advfirewall firewall add rule name="aws-cred-svc" localip=169.254.169.254 localport=80,12319 protocol=tcp dir=in enable=yes action=block
    netsh interface portproxy add v4tov4 listenport=80 listenaddress=169.254.169.254 connectport=12319 connectaddress=169.254.169.254
}