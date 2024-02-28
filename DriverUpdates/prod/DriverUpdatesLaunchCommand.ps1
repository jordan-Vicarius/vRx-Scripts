#vRx Driverlauncher
Powershell.exe -executionpolicy bypass -command "rm -Force 'C:\Program Files\Vicarius\temp\vRxDrivers\driverUpdateLauncherLogs.txt' -ErrorAction SilentlyContinue; rm -force 'C:\Program Files\Vicarius\temp\vRxDrivers\DriverUpdates\DriverUpdates-MSUpdatelogs.txt' -ErrorAction SilentlyContinue; rm -force 'C:\Program Files\Vicarius\temp\vRxDrivers\PendingReboots\PendingRebootlogs.txt' -ErrorAction SilentlyContinue"
Powershell.exe -executionpolicy bypass -command "Expand-Archive -path '.\vRxDriverupdates.zip' -DestinationPath '.\'"
Powershell.exe -executionpolicy bypass -command ".\DriverUpdateLauncher.ps1"
Powershell.exe -executionpolicy bypass -command "rm -Recurse -Force 'C:\Program Files\Vicarius\temp\vRxDrivers\DriverUpdates' -ErrorAction SilentlyContinue"