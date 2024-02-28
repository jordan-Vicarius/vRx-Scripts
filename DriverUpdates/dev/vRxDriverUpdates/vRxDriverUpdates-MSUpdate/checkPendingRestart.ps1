$loc = Get-location
$param1=$args[0]
#write-host $param1 
$rootPath = "C:\Program Files\Vicarius\temp\vRxDrivers\"
$vRxRestartFolder = "$rootPath\PendingReboots"
if (!(test-path $vRxRestartFolder)) {
    mkdir $vRxRestartFolder
}
#import-module .\RunAsUser\runasuser.psm1
$logFile = "$rootPath\PendingReboots\PendingRebootlogs.txt"
$scriptblock = {
    $restartArr = @()
    $logFile = "$rootPath\PendingReboots\PendingRebootlogs.txt"
    function Restart-window ($restartReason) {
        ## LEGACY REBOOT PROMPTS
        # Do not all user to cancel - postpone for up to 4 hours with original counter at 2 hours - 
        #& "C:\Program Files\Vicarius\Topia\SafeReboot64.exe" -o 1 -requestor 1 -s 120 -i 60 -m 300 -w 120 -n \"Topia\" -u \"Topia\" -power 4

        #Allow user to cancel 
        #& "C:\Program Files\Vicarius\Topia\SafeReboot64.exe" -o 7 -requestor 1 -s 120 -i 60 -m 300 -w 120 -n \"Topia\" -u \"Topia\" -power 4 -us

        ## REBOOT PROMPTS
        $SecondsUntilReboot = 600 #initial timer in seconds
        $allowCancel = "false" #Options: true/false  /popup=reboot /allowcancel=' + $allowCancel + ' /timetoreboot
        $rebootdeadline = 5 #Reboot deadline in hours from now
        $minutesUntilReboot = $SecondsUntilReboot / 60
        #$minutesUntilReboot
        $hoursUntilReboot = [math]::Ceiling($minutesUntilReboot / 60)
        #$hoursUntilReboot
        $RebootString = '"C:\Program Files\Vicarius\topia\vrx_dialog.exe" /popup=reboot /timetoreboot=' + $hoursUntilReboot + ' /deadline=' + $rebootdeadline
        & cmd.exe /c "$RebootString"

    }
    Function write-log ($LogMessage) {
    
        Write-EventLog -LogName Application -Source "vRx" -Message $LogMessage -EventID "10001"

    }
    function Test-RegistryKey {
            #[OutputType('bool')]
            #[CmdletBinding()]
            param
            (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]$Key
            )
    
            $ErrorActionPreference = 'Stop'
            $regVal = Get-Item -Path $Key -ErrorAction Ignore
            if (($regVal)) {
            $count = "N/A"
            $regOBJ = New-Object pscustomobject
            $regOBJ | Add-Member -type NoteProperty -Name "Key" -Value $key
            $regOBJ | Add-Member -type NoteProperty -Name "Value" -Value "N/A"
            $regOBJ | Add-Member -type NoteProperty  -Name "Count" -Value $Count

            return $regOBJ
        }
        }
    function Test-RegistryValue {
        #[OutputType('bool')]
        #[CmdletBinding()]
        param
        (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Key,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Value
        )
    
        $ErrorActionPreference = 'Stop'
        $regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore
        if (($regVal)) {
            $count = $regVal.($Value).Count
            $regOBJ = New-Object pscustomobject
            $regOBJ | Add-Member -type NoteProperty -Name "Key" -Value $key
            $regOBJ | Add-Member -type NoteProperty -Name "Value" -Value $Value
            $regOBJ | Add-Member -type NoteProperty  -Name "Count" -Value $Count

            return $regOBJ
        }
    }
    function Test-RegistryValueNotNull {

        param
        (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Key,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Value
        )
    
        $ErrorActionPreference = 'Stop'

        $regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore
        if (($regVal) -and $regVal.($Value)) {
            $count = $regVal.($Value).Count
            $regOBJ = New-Object pscustomobject
            $regOBJ | Add-Member -type NoteProperty -Name "Key" -Value $key
            $regOBJ | Add-Member -type NoteProperty -Name "Value" -Value $Value
            $regOBJ | Add-Member -type NoteProperty  -Name "Count" -Value $Count

            return $regOBJ
        }
    }

    $tests = @(
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
            { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
            { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' }
            { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' }
            { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations2' }
            { 
                # Added test to check first if key exists, using "ErrorAction ignore" will incorrectly return $true
                'HKLM:\SOFTWARE\Microsoft\Updates' | Where-Object { test-path $_ -PathType Container } | ForEach-Object {            
                    (Get-ItemProperty -Path $_ -Name 'UpdateExeVolatile' -ErrorAction Ignore | Select-Object -ExpandProperty UpdateExeVolatile) -ne 0 
                }
            }
            { Test-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Value 'DVDRebootSignal' }
            { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps' }
            { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'JoinDomain' }
            { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'AvoidSpnSet' }
            {
                # Added test to check first if keys exists, if not each group will return $Null
                # May need to evaluate what it means if one or both of these keys do not exist
                ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' | Where-Object { test-path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } ) -ne 
                ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' | Where-Object { Test-Path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } )
            }
            {
                # Added test to check first if key exists
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' | Where-Object { 
                    (Test-Path $_) -and (Get-ChildItem -Path $_) } | ForEach-Object { $true }
            }
            #{ $True }
        )
    "Checking for pending Reboots" | out-file -FilePath $logFile -append 
    foreach ($test in $tests) {
        
        #$test
        if (& $test){
            #"Reboot Required" | out-file -FilePath $logFile -append 
            #$test | out-file -FilePath $logFile -append 
            $restartArr += (& $test)
        }
    }


    if ($restartArr) {
        $logxml = $restartArr | ConvertTo-Json
        write-log $logxml
        Write-host $logxml
        "Restart fields" | out-file -FilePath $logFile -append 
        $logxml | out-file -FilePath $logFile -Append
        "Prompting user for Restart " | out-file -FilePath $logFile -Append
        Restart-window $logxml
    }
    else {
        "No Pending Reboots" | out-file -FilePath $logFile -append 
    }
}


#Invoke-AsCurrentUser -ScriptBlock $scriptblock
$null = start-job -name "Check Pending Reboot" -ScriptBlock $scriptblock 
$i = 0
do {
   Start-Sleep -s 60 
  "Querying Job Status...$i" | out-file -FilePath $logFile -Append
  $jobStatus = get-job -name 'Check Pending Reboot'
  if ($jobStatus.State -eq "Completed") {
    "Job Status: Complete" | out-file -FilePath $logFile -Append
    Get-content -Path $logFile 
    $i = 4
    $status = "exit"
  } 
  elseif ($jobStatus.State -eq "Failed") {
    "Job Status: Complete" | out-file -FilePath $logFile -Append
    Get-content -Path $logFile 
    $i = 4
    $status = "exit"
  }
  $i += 1 
}while ($i -lt 4)
if (!($status -eq "exit")) {
    Get-content -Path $logFile 
}
