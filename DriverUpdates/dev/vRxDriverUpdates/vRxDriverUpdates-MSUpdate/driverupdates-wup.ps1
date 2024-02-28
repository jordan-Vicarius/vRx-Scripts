begin {
    $rootPath = "C:\Program Files\Vicarius\temp\vRxDrivers\"
    $date = get-date -Format dd-MM-yyyy-HH:mm:ss
    $DriverupdateLogs = "-LOG-vRxDriverUpdates: "
    $logFile = "$rootPath\DriverUpdates\DriverUpdates-MSUpdatelogs.txt"
    $date + $DriverupdateLogs + " Installing Dependecies " | Out-File -FilePath $logFile -append
    $installedPackProviderNuget = $false
    if (!(test-path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget")) {
        cp -Recurse "$rootPath\DriverUpdates\Dependencies\nuget" "C:\Program Files\PackageManagement\ProviderAssemblies\nuget"
        Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208
        Install-PackageProvider -name NuGet
        $installedPackProviderNuget = $true
        $date + $DriverupdateLogs + " Nuget Installed: " + $installedPackProviderNuget | Out-File -FilePath $logFile -append
    }   
    $psRepos = Get-PSRepository
    $date + $DriverupdateLogs +"Current Repos"  | Out-File -FilePath $logFile -Append
    $psRepos | Out-File -FilePath $logFile -Append
    $repoName = "PSUpdateLocal"
    Register-PSRepository -Name $repoName -SourceLocation "$rootPath\DriverUpdates\" -PublishLocation "$rootPath\DriverUpdates\" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    $psRepo1 = Get-PSRepository
    $psRepo1  | Out-File -FilePath $logFile -Append
    $date + $DriverupdateLogs +"Installing PSWindowsUpdate Module"  | Out-File -FilePath $logFile -Append
    Install-Module -name PSWindowsUpdate -Repository $repoName -ErrorAction SilentlyContinue
    import-module -name PSWIndowsUpdate
    Get-module | out-File -FilePath $logFile -Append
    Get-installedmodule | out-File -FilePath $logFile -Append
    # If the PowerShell Modules Folder is non-existing, it will be created.
    if ($false -eq (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules)) {
        New-Item -ItemType Directory -Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules1 -Force
    }
    # Import the PowerShell Module
    $ScriptPath = Get-Location
    #Import-Module $ScriptPath\PSWindowsUpdate -Force
    # Specify the path usage of Windows Update registry keys
    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    $date + $DriverupdateLogs +"Get Registry Properties from " + $Path  | Out-File -FilePath $logFile -Append
    $windowsRegObj = Get-ItemProperty $Path\WindowsUpdate -ErrorAction SilentlyContinue
    $windowsRegObj | Out-File -FilePath $logFile -Append
}
# Updates and Driver download
process {
    $date = get-date -Format dd-MM-yyyy-HH:mm:ss
    # If the necessary keys are non-existing, they will be created
    if ($false -eq (Test-Path $Path\WindowsUpdate)) {
        $WindowsUpdateRegCreated = $true
        New-Item -Path $Path -Name WindowsUpdate
        New-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -PropertyType DWord -Value '0'
        New-ItemProperty $Path\WindowsUpdate -Name WUServer -PropertyType DWord -Value $null
        New-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -PropertyType DWord -Value $null
    }
    else {
        
        # If the value of the keys are incorrect, they will be modified
        try {
            Set-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -value "0" -ErrorAction SilentlyContinue
            Set-ItemProperty $Path\WindowsUpdate -Name WUServer -Value $null -ErrorAction SilentlyContinue
            Set-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -Value $null -ErrorAction SilentlyContinue
            $WindowsUpdateRegCreated = $false
        }
        catch {
            Write-Output 'Skipped modifying registry keys'
        }
    }
    # Add ServiceID for Windows Update
    Get-WUServiceManager | Out-File -FilePath $logFile -Append
    $date + $DriverupdateLogs +"Adding Windows Update Servicer"  | Out-File -FilePath $logFile -Append
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false | Out-File -FilePath $logFile -Append
    if (!(Get-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d)) {
        $date + $DriverupdateLogs +"Failed to add Servicer: Microsoft Update 7971f918-a847-4430-9279-4a52d1efe18d"  | Out-File -FilePath $logFile -Append   
        $date + $DriverupdateLogs +"Continue with Script "  | Out-File -FilePath $logFile -Append 
        Get-WindowsUpdateLog -logPath "$rootPath\DriverUpdates\windowsupdate.log"
        $collectWinLogs = $True

    }
    # Pause and give the service time to update
    Start-Sleep 30
    # Scan against Microsoft, accepting all drivers
    #Get-WUInstall -MicrosoftUpdate -AcceptAll
    # Scaning against Microsoft for all Driver types, and accepting all
    #write-host "Searching for updates" 
    #"Searching for updates"  | Out-File -FilePath "$rootPath\DriverUpdates-MSUpdate\logs.txt" -Append
    #Get-WindowsUpdate -MicrosoftUpdate -UpdateType Driver -AcceptAll -Verbose
    #Write-host "Downloading Updates"
    $date = get-date -Format dd-MM-yyyy-HH:mm:ss  
    $date + $DriverupdateLogs +"Search for and Downloading Updates"  | Out-File -FilePath $logFile -Append
    Get-WindowsUpdate -Download -MicrosoftUpdate -UpdateType Driver -AcceptAll | Out-File -FilePath $logFile -Append
    #Write-host "Installing Updates" 
    $date + $DriverupdateLogs +"Installing Updates" | Out-File -FilePath $logFile -Append
    Get-WindowsUpdate -Install -MicrosoftUpdate -UpdateType Driver -AcceptAll | Out-File -FilePath $logFile -Append
    # Scanning against Microsoft for all Software Updates, and installing all, ignoring a reboot
    #Get-WUInstall -MicrosoftUpdate Software -AcceptAll -IgnoreReboot
    $date = get-date -Format dd-MM-yyyy-HH:mm:ss
    $date + $DriverupdateLogs +"Checking for Pending Reboots" | Out-File -FilePath $logFile -Append
    Get-WUInstallerStatus | Out-File -FilePath $logFile -Append
    $Reboot = Get-WURebootStatus -silent 
    $date + $DriverupdateLogs +"Pending Reboot: " + $Reboot | Out-File -FilePath $logFile -Append
    #$Reboot | Out-File -FilePath $logFile -Append
    #$reboot.required = "True"
    if ($Reboot) {
        & "$rootPath\DriverUpdates\checkPendingRestart.ps1"
        $i = 0
        do {
            start-sleep -s 60 
            Write-host "Prompting for Restart "
            $jobstatus = get-job -name "Check Pending Reboot"

            if ($jobstatus.State -eq "Completed") {
                $date + $DriverupdateLogs +"Prompted user for Reboot"  | Out-File -FilePath $logFile -Append
                $i = 4
            }
            else {
                $date + $DriverupdateLogs +"Checking for reboot flag"  | Out-File -FilePath $logFile -Append
                start-sleep -s 30
                $i += 1

            }
        }while ( $i -lt 4)
    }
}
# End of the script
end {
    $date = get-date -Format dd-MM-yyyy-HH:mm:ss
    if ($collectWinLogs) {
        $date +"*****************************" | Out-File -FilePath $logFile -Append
        $date +"WindowsUpdateLogs: Failed to add Servicer: 7971f918-a847-4430-9279-4a52d1efe18d" | Out-File -FilePath $logFile -Append
        Get-Content -Path "$rootPath\DriverUpdates\windowsupdate.log" | Out-File -FilePath $logFile -Append
        $date +"*****************************" | Out-File -FilePath $logFile -Append
    }
    #Write-host "Removing WU Service Manager" 
    $date + $DriverupdateLogs +"Removing WU Service Manager" | Out-File -FilePath $logFile -Append
    Remove-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false | Out-File -FilePath $logFile -Append
    Unregister-PSRepository -Name $repoName 
    uninstall-module -name PSWindowsUpdate -Force
    if ($installedPackProviderNuget) {
        Remove-Item -Recurse -Force "C:\Program Files\PackageManagement\ProviderAssemblies\nuget"
    }
    if ($WindowsUpdateRegCreated) {
        Remove-Item -Path $Path -Name WindowsUpdate
    }
    elseif (!($WindowsUpdateRegCreated)) {
        Set-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -value $windowsRegObj.DisableDualScan -ErrorAction SilentlyContinue
        Set-ItemProperty $Path\WindowsUpdate -Name WUServer -Value $windowsRegObj.WUServer -ErrorAction SilentlyContinue
        Set-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -Value $windowsRegObj.WUStatusServer -ErrorAction SilentlyContinue
    }
    $date + $DriverupdateLogs +"Update Job Complete" | Out-File -FilePath $logFile -Append
    $date + $DriverupdateLogs +"************************************" | Out-File -FilePath $logFile -Append

}