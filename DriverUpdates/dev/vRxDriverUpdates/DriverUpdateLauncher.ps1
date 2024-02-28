$rootPath = "C:\Program Files\Vicarius\temp\vRxDrivers"
$vRxTempFolder = "C:\Program Files\Vicarius\temp\vRxDrivers\"
$date = get-date -Format dd-MM-yyyy-HH:mm:ss
$DriverUpdateLauncherLogs = "$rootPath\driverUpdateLauncherLogs.txt"
if (!(test-path $vRxTempFolder)) {
   $null = mkdir $vRxTempFolder 
}
$vRxDriverUpdates = "$rootPath\DriverUpdates"
if (!(test-path $vRxDriverUpdates)) {
   $null = mkdir $vRxDriverUpdates 
}
$date + "Starting Driver Updates Task" | Out-File -FilePath $DriverUpdateLauncherLogs -append
$wuauservObj = get-service -name wuauserv | Select -Property Name,Status,Starttype
$date + "Checking Windows update Status" | Out-File -FilePath $DriverUpdateLauncherLogs -append
$wuauservObj | out-file -FilePath $DriverUpdateLauncherLogs -append
$date + "Starting Windows Update Service" | Out-File -FilePath $DriverUpdateLauncherLogs -append
$null = Set-service -name Wuauserv -StartupType Manual -Status Running
get-service -name wuauserv | Select -Property Name,Status,Starttype | Out-File -FilePath $DriverUpdateLauncherLogs -append
$date + "Checking Dir " + $vRxTempFolder | Out-File -FilePath $DriverUpdateLauncherLogs -append

$date + "Copying MSUpdate.zip" | Out-File -FilePath $DriverUpdateLauncherLogs -append
cp .\vRxDriverUpdates-MSUpdate.zip "$rootPath\DriverUpdates\vRxDriverUpdates-MSUpdate.zip"
cd $vRxDriverUpdates
$date + "Expanding MSUpdate.zip" | Out-File -FilePath $DriverUpdateLauncherLogs -append
Expand-Archive -path .\vRxDriverUpdates-MSUpdate.zip -DestinationPath .\ -ErrorAction SilentlyContinue
$MSUpdateszipStatus = test-path -Path .\driverupdates-wup.ps1
$date + " Expanded vRxDriverUpdates-MSUpdate.zip: " + $MSUpdateszipStatus | Out-File -FilePath $DriverUpdateLauncherLogs -append
$date + "Starting Update Job 'vRxDriverUpdates'" | Out-File -FilePath $DriverUpdateLauncherLogs -append
$null = Start-job -name "vRxDriverUpdates" -FilePath .\driverupdates-wup.ps1
$i = 0
do {
start-sleep -s 150
$date = get-date -Format dd-MM-yyyy-HH:mm:ss 
$date + "Updates in Progress" | Out-File -FilePath $DriverUpdateLauncherLogs -append
$jobstatus = get-job -name "vRxDriverUpdates" 
$jobStatus | out-file -FilePath $DriverUpdateLauncherLogs -append
if ($jobstatus.State -eq "Completed") {
    $date + "Job Completed Collecting Logs" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $logsfile = get-content "$rootPath\DriverUpdates\DriverUpdates-MSUpdatelogs.txt"
    $date + "*********** DriverUpdates Job Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $logsfile | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $date + "*********** END DriverUpdates Job Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    if (Test-Path "$rootPath\PendingReboots\PendingRebootlogs.txt") {
        $reboot = get-content "$rootPath\PendingReboots\PendingRebootlogs.txt"
        $date + "*********** Check Reboot Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
        $reboot | Out-File -FilePath $DriverUpdateLauncherLogs -append
        $date + "*********** END Reboot Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    }
    $i = 10
}
elseif ($jobstatus.State -eq "Running") {
    $date + " Job still running" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $i += 1
}
else {
    $date + "Job Failed" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $date + "Job Failed Collecting Logs" | Out-File -FilePath $DriverUpdateLauncherLogs -append

    $logsfile = get-content "$rootPath\DriverUpdates\DriverUpdates-MSUpdatelogs.txt" -ErrorAction SilentlyContinue
    $date + "*********** DriverUpdates Job Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $logsfile | Out-File -FilePath $DriverUpdateLauncherLogs -append
    $date + "*********** END DriverUpdates Job Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    if (Test-Path "$rootPath\PendingReboots\PendingRebootlogs.txt") {
        $reboot = get-content "$rootPath\PendingReboots\PendingRebootlogs.txt" -ErrorAction SilentlyContinue
        $date + "*********** Check Reboot Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
        $reboot | Out-File -FilePath $DriverUpdateLauncherLogs -append
        $date + "*********** END Reboot Logs ****************" | Out-File -FilePath $DriverUpdateLauncherLogs -append
    }
    $i = 10
}
}while ( $i -lt 10)
$date = get-date -Format dd-MM-yyyy-HH:mm:ss 
uninstall-module -name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
$date + "Stopping Windows Update Service" | Out-File -FilePath $DriverUpdateLauncherLogs -append
get-service -name wuauserv | stop-service
$date + "Returning service to original State" | Out-File -FilePath $DriverUpdateLauncherLogs -append
Set-service -name WUAUServ -StartupType $wuauservObj.StartType -Status $wuauservObj.Status
get-service -name wuauserv | Select -Property Name,Status,Starttype | Out-File -FilePath $DriverUpdateLauncherLogs -append
$LauncherLogs = get-content $DriverUpdateLauncherLogs
$LauncherLogs
#Save Logs 
$logsPath = "C:\Program Files\Vicarius\vRxDriverLogs"
$null = mkdir "$logsPath" -ErrorAction SilentlyContinue
cp "$DriverUpdateLauncherLogs" "$logsPath\driverUpdateLauncherLogs-$date.txt" -ErrorAction silentlyContinue
cp "$rootPath\DriverUpdates\DriverUpdates-MSUpdatelogs.txt" "$logsPath\DriverUpdates-MSUpdatelogs-$date.txt" -ErrorAction silentlyContinue
cp "$rootPath\PendingReboots\PendingRebootlogs.txt" "$logsPath\PendingRebootlogs-$date.txt" -ErrorAction silentlyContinue
#Cleanup 
rm -Force $DriverUpdateLauncherLogs -ErrorAction SilentlyContinue
rm -force "$rootPath\DriverUpdates\DriverUpdates-MSUpdatelogs.txt" -ErrorAction SilentlyContinue
rm -force "$rootPath\PendingReboots\PendingRebootlogs.txt" -ErrorAction SilentlyContinue
remove-item -Recurse -Force -Path "$rootPath\PendingReboots"
