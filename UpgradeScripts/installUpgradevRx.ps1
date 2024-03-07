$filesDir = "C:\Temp\Topia\AgentUpgrade\"
if ((test-path "$filesdir\unified")) {
    remove-item -r -f "$filesdir\unified" 
}
mkdir $filesDir
mkdir "$filesdir\unified"
Start-Transcript -Path "C:\Program Files\Vicarius\vrxUpgradeScriptLog.txt" -Verbose
$logFile = "C:\Temp\Topia\AgentUpgrade\upgradelog.log"
test-path "$filesDir\vRx.exe"
$date = get-date -Format MM-dd-yyyy_mmhhss
$date | Out-File -FilePath $logFile 

$minimumTopiaVersion = [system.version]"5.1.5"
#insallation Command Variables 
$secretKey = ""
$dashboard = ""
$hostname = "https://$dashboard-api-gateway.vicarius.cloud"
$endpointTag = "" #Key:Value,Key1:value1
$proxy = "" #FQDN/IP:port
$forceUninstall = $false #Force Uninstallation and Reinstallation of vRx agent
$reinstallNotRegistered = $true  # IF a valid agent registraty cannot be determine, reinstall the agent

#OS Architecture 
$osarch = [Environment]::Is64BitOperatingSystem
 # Enter your Powershell installation command
 function checkTopiaInstalled () {
    $rtnObj = New-Object -TypeName PScustomObject
    $app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString | Where-object {$_.DisplayName -like "*Topia*"}
    $app1 = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString | Where-object {$_.DisplayName -like "*Topia*"}
    if ($app) {
        $app | add-member -MemberType NoteProperty -name "Topia" -Value $true
    }
    elseif ($app1) {
        $app = $app1
        $app | add-member -MemberType NoteProperty -name "Topia" -Value $true
    }

    else {
        $app = New-Object -TypeName PScustomObject
        $app | add-member -MemberType NoteProperty -name "Topia" -Value $false
    }
    
    return $app
}
function CleanupvRx () {
    get-service -name Topia | Stop-Service -ErrorAction SilentlyContinue
    remove-item -force 'C:\Program Files\Vicarius\topia\topiad.exe' -ErrorAction SilentlyContinue
    try {
        $app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString | Where-object {$_.DisplayName -like "*Topia*"}
        $app1 = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString,PSPath | Where-object {$_.DisplayName -like "*Topia*"}
        if ($app) {
            $app = Get-WmiObject -Class Win32_Product -Filter "Name = 'Topia'"
            $null = $app.Uninstall()
        }
        if ($app1) {
            $uninst = $app1.UninstallString
            $null = start-job -name "UninstallTopia" -ScriptBlock {start-sleep -s 1; & cmd /c $uninst /S }
            slart-sleep -s 10
        }
    }

    catch{"Failed to uninstall" | out-file $logFile -Append}
    try {

        $null = sc.exe delete topia  
        $null = sc.exe topiaguard
    }
    catch {"Failed to delete topia service" | out-file $logFile -Append}
    try {

        Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\topia | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-Item HKLM:\SYSTEM\CurrentControlSet\Topia | Remove-Item -Force -erroraction SilentlyContinue
        if ((Get-ItemProperty HKLM:\SOFTWARE\Classes\Installer\Products\0D91FDE0D0D76CC47830E1D32C6BED29 -name ProductName | select ProductName -erroraction SilentlyContinue) -match "Topia")
        {
            Get-Item HKLM:\SOFTWARE\Classes\Installer\Products\0D91FDE0D0D76CC47830E1D32C6BED29 | Remove-Item -Force -erroraction SilentlyContinue
        }
        if ((Get-ItemProperty HKLM:\SOFTWARE\Classes\Installer\Products\0D91FDE0D0D76CC47830E1D32C6BED29 -name ProductName | select ProductName -erroraction SilentlyContinue) -match "Topia"){
            reg.exe delete HKLM:\SOFTWARE\Classes\Installer\Products\0D91FDE0D0D76CC47830E1D32C6BED29 /f
        }   
    }
    catch{"Failed to remove registry key" | out-file $logFile -Append}
    try {
        if (test-path "C:\Program Files\Vicarius\Topia\Uninstall.exe"){
            & "C:\Program Files\Vicarius\Topia\Uninstall.exe" /S
            start-sleep 10
        }
    }catch{"Failed to uninstall" | out-file $logFile -Append}
    try {
        if (Get-ItemProperty  "HKLM:\SOFTWARE\Vicarius" -ErrorAction SilentlyContinue){
            Get-item "HKLM:\SOFTWARE\Vicarius" -ErrorAction SilentlyContinue | remove-item -Force -Recurse -ErrorAction SilentlyContinue
        }
        
    }catch {"Failed to remove registry items" | out-file $logFile -Append}
    try {
        remove-item -Force -Recurse -path "C:\Program Files\Vicarius\Topia\" -ErrorAction SilentlyContinue
    }catch {"Failed to remove programs dir" | out-file $logFile -Append}

}
function installvRx () {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $hostname,
        [string]
        $secretKey,
        [string]
        $filesdir,
        [string]
        $logFile,
        $argsList
    )
    "Installing vRx agent" | out-file $logFile -Append
    if (!(test-path "$filesdir\unified\vRx.exe")) {
        $OriginalPref = $ProgressPreference # Default is 'Continue'
        $ProgressPreference = "SilentlyContinue"
        $tlsver = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-webrequest "https://vicarius-installer.s3.amazonaws.com/UnifiedAgent/vRx.exe" -OutFile "$filesdir\unified\vRx.exe"
        "Downloaded vrx.exe = $forceUninstall" | out-file -FilePath $logfile -append
        test-path "$filesdir\unified\vRx.exe" | out-file -FilePath $logfile -append
        $ProgressPreference = $OriginalPref
        [Net.ServicePointManager]::SecurityProtocol = $tlsver

    }
    "Creating Installation Command based on Arguments" | Out-File -FilePath $logFile -Append
    $insString = "C:\temp\Topia\AgentUpgrade\Unified\vRx.exe /SecretKey=$secretKey /Hostname=$hostname /AgentType=LocalAgent"
    if ($argsList.endpointTag){
        $insString += " /EndpointTag=" + $argsList.endpointTag
    }
    if ($argsList.proxy) {
        $insString += " /ProxyAddress=" + $argsList.proxy
    }
    "Executing Installation Command" | Out-File -FilePath $logFile -Append
    powershell.exe -executionpolicy bypass -command $insString
    "InstallationString: $insstring" | Out-File $logFile -Append
    
}
function checkvRxConnection() {
    function Check70() {
        $vRxLog = get-content "C:\Program Files\Vicarius\Topia\Trace\TopiaTrace.log" -tail 70
        if ($vrxLog | select-string "Error"){
            $errors = $vrxLog | select-string "Error" 
            $conErrors = $errors | select-string "ConnectionManager::Init(): Init Failed", "Parameter name: url", "An invalid URI string", "unauthorized", "The hostname could not be parsed", "Failed to register!"
            try {
            $lastConErr = [string]$conErrors[$conErrors.length-1]
            }catch {$lastConEr = ""} 
            $registrations = $vrxLog | select-string "Successful registration."
            try {
            $lastReg  = [string]$registrations[$registrations.length-1]
            } catch {$lastReg = ""}
            try {
            $lastConErrDate = [datetime]::ParseExact($lastConErr.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastConErrDate = ""}
            try {
            $lastRegDate = [datetime]::ParseExact($lastReg.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastRegDate = ""}
            if ($lastRegDate -gt $lastConErrDate){
                Return "Registered", $lastRegDate, $lastConErrDate
            }
            Else {
                if (!($lastRegDate)){
                    $lastRegDate = "0"
                }
                if (!($lastConErrDate)){
                    $lastConErrDate = "0"
                }
                Return "RegistrationFailed", $lastRegDate, $lastConErrDate
            }
        }
        else {
            $errors = $vrxLog | select-string "Error" 
            $conErrors = $errors | select-string "ConnectionManager::Init(): Init Failed", "Parameter name: url", "An invalid URI string", "unauthorized", "The hostname could not be parsed", "Failed to register!"
            try {
            $lastConErr = [string]$conErrors[$conErrors.length-1]
            }catch {$lastConEr = ""} 
            $registrations = $vrxLog | select-string "Successful registration."
            try {
            $lastReg  = [string]$registrations[$registrations.length-1]
            } catch {$lastReg = ""}
            try {
            $lastConErrDate = [datetime]::ParseExact($lastConErr.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastConErrDate = ""}
            try {
            $lastRegDate = [datetime]::ParseExact($lastReg.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastRegDate = ""}
            if ($lastRegDate -gt $lastConErrDate){
                Return "Registered", $lastRegDate, $lastConErrDate
            }
            Else {
                if (!($lastRegDate)){
                    $lastRegDate = "0"
                }
                if (!($lastConErrDate)){
                    $lastConErrDate = "0"
                }
                Return "NoErrors", $lastRegDate, $lastConErrDate
            }  
        }
    }
    function check1000() {
        $vRxLog = get-content "C:\Program Files\Vicarius\Topia\Trace\TopiaTrace.log" -tail 1000
        if ($vrxLog | select-string "Error"){
            $errors = $vrxLog | select-string "Error" 
            $conErrors = $errors | select-string "ConnectionManager::Init(): Init Failed", "Parameter name: url", "An invalid URI string", "unauthorized", "The hostname could not be parsed", "Failed to register!", "Error: resolve: No such host is known"
            $registrations = $vrxLog | select-string "Successful registration.", "Ws connection is established"
            try {
            $lastConErr = [string]$conErrors[$conErrors.length-1]
            }catch {$lastConEr = ""} 
            try {
            $lastReg  = [string]$registrations[$registrations.length-1]
            } catch {$lastReg = ""}
            if ($lastConErr.Length -lt 1) {
                $LastConErr = "2000-01-01 00:00:00"
            }
            else{
                $lastConErrDate = ""
                $LastConErr = $lastConErr.Substring(1,19)
                $lastConErr = $lastConErr.trim()
            }
            if ($lastReg.Length -lt 1) {
                $lastReg = "2000-01-01 00:00:00"
            }
            else{
                $lastConErrDate = ""
                $lastReg = $lastReg.Substring(1,19)
                $lastReg = $lastReg.trim()
            }
            $lastConErrDate = [datetime]::parseexact($lastConErr,'yyyy-MM-dd HH:mm:ss', $null)
            $lastRegDate = [datetime]::ParseExact($lastReg, 'yyyy-MM-dd HH:mm:ss',$null)
            if ($lastRegDate -gt $lastConErrDate){
                Return "Registered", $lastRegDate, $lastConErrDate
            }
            Else {
                if (!($lastRegDate)){
                    $lastRegDate = "0"
                }
                if (!($lastConErrDate)){
                    $lastConErrDate = "0"
                }
                Return "RegistrationFailed", $lastRegDate, $lastConErrDate
            }
        }
        else {
            $errors = $vrxLog | select-string "Error" 
            $conErrors = $errors | select-string "ConnectionManager::Init(): Init Failed", "Parameter name: url", "An invalid URI string", "unauthorized", "The hostname could not be parsed", "Failed to register!"
            try {
            $lastConErr = [string]$conErrors[$conErrors.length-1]
            }catch {$lastConEr = ""} 
            $registrations = $vrxLog | select-string "Successful registration."
            try {
            $lastReg  = [string]$registrations[$registrations.length-1]
            } catch {$lastReg = ""}
            try {
            $lastConErrDate = [datetime]::ParseExact($lastConErr.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastConErrDate = ""}
            try {
            $lastRegDate = [datetime]::ParseExact($lastReg.Substring(0,19), 'yyyy-MM-dd hh:mm:ss',$null)
            } catch {$lastRegDate = ""}
            if ($lastRegDate -gt $lastConErrDate){
                Return "Registered", $lastRegDate, $lastConErrDate
            }
            Else {
                if (!($lastRegDate)){
                    $lastRegDate = "0"
                }
                if (!($lastConErrDate)){
                    $lastConErrDate = "0"
                }
                Return "NoErrors", $lastRegDate, $lastConErrDate
            }  
        }
    }
    $ErrorCheck,$lastRegDate,$lastConErrDate = Check70
    if ($ErrorCheck -eq "RegistrationFailed"){
        return $ErrorCheck,$lastRegDate,$lastConErrDate
    }
    elseif($ErrorCheck -eq "Registered"){
        return $ErrorCheck,$lastRegDate,$lastConErrDate
    }
    elseif ($ErrorCheck -eq "NoErrors"){
        $ErrorCheck,$lastRegDate,$lastConErrDate = check1000
        return $ErrorCheck,$lastRegDate,$lastConErrDate
    }
    else {
        $ErrorCheck,$lastRegDate,$lastConErrDate = check1000
        return $ErrorCheck,$lastRegDate,$lastConErrDate
    }
}
function setconfigVars ($installedVersion) {
    if ($installedVersion.Major -eq "4"){
        $config_file = "C:\Program Files\Vicarius\Topia\Topia.exe.config"
        [xml]$xmlDoc = Get-Content $config_file 
        $secretKey = $xmlDoc.configuration.appSettings.ChildNodes | ?{$_.key -eq "SecretKey"}
        $hostname = $xmlDoc.configuration.appSettings.ChildNodes | ?{$_.key -eq "Hostname"}
        $endpointTag = $xmlDoc.configuration.appSettings.ChildNodes | ?{$_.key -eq "EndpointTag"}
        Return $secretKey.value, $hostname.value, $endpointTag.value
    }
    elseif ($installedVersion.Major -eq "5"){
        $config_file = "C:\Program Files\Vicarius\Topia\topia.config"
        $jsonConf = Get-Content $config_file | convertfrom-json
        $secretkey = $jsonConf.secret_key
        $hostname = $jsonConf.server_name
        $endpointTag = $jsonConf.endpoint_tag
        Return $secretKey, $hostname, $endpointTag
    }

}
if ($osarch) {
#Check if Topia is installed - Version Check
$vRxInstall = checkTopiaInstalled
$installedVersion = [system.version]$vRxInstall.DisplayVersion
#Uninstall Topia
if (($installedVersion -lt $minimumTopiaVersion) -or $forceUninstall) {
    Write-host "vRx is not installed at version $minimumTopiaVersion or ForceUninstall = True"
    write-host "vRx Version: " $vRxInstall.DisplayVersion 
    Write-host "ForceUninstall = $forceUninstall"
    Write-host "Collected Asset Host Variables"
    "vRx is not installed at version $minimumTopiaVersion or ForceUninstall = True" | Out-File -FilePath $logFile -Append 
    "vRx Version: " + $vRxInstall.DisplayVersion | out-file -FilePath $logfile -append
    "ForceUninstall = $forceUninstall" | out-file -FilePath $logfile -append
    "Cleaning Installation" | Out-File -FilePath $logFile -Append 
    "Collected Asset Host Variables" | Out-File -FilePath $logFile -Append 
    $SKey,$hname,$etag = setconfigVars $installedVersion
    $SKey | Out-File "$filesDir\secretkey.txt"
    $hname | Out-File "$filesDir\hname.txt"
    $etag | Out-File "$filesDir\etag.txt"
    if ($etag.Length -gt 1){
        $configSet = $true
    }
    CleanupvRx
    $topiaSVCStatus = $false
}
else {
    Write-host "vRx Is installed "
    write-host "vRx Version: " $installedVersion
    "vRx Version: " + $installedVersion | Out-File -FilePath $logFile -Append 
    "vRx Is installed "+ $installedVersionon | out-file -FilePath $logfile -append
}
#Confirm Topia is uninstalled - Version Check
$vRxInstall = checkTopiaInstalled
#Install Unified
if (!($vRxInstall.Topia)) {
    write-host "installing Topia"
    "Installing Topia" | Out-File -FilePath $logFile -Append
    if ($secretKey.length -lt 1) {
        if ($Skey.length -gt 1) {
            $secretKey = $SKey
        }
        else {
            $secretKey = get-content "$filesDir\secretkey.txt"
        }
    }
    if ($dashboard.length -lt 1) {
        if ($hname.length -gt 1) {
            $hostname = $hname
        }
        else {
            $hostname = get-content "$filesDir\hname.txt"
        }
    }
    if ($endpointTag.length -lt 1) {
        $endpointTag = $etag
        if ($etag.length -gt 1) {
            $endpointTag = $etag
        }
        else {
            $endpointTag = get-content "$filesDir\etag.txt"
        }
    }
    $argsList = New-Object PScustomObject
    if ($endpointTag) {
        $argsList | Add-Member -MemberType NoteProperty -Name "EndpointTag" -Value $endpointTag
    }
    if ($proxy) {
        $argsList | Add-Member -MemberType NoteProperty -Name "Proxy" -Value $Proxy
    }
    installvRx -secretKey $secretKey -hostname $hostname -argslist $argsList -logFile $logFile -filesdir $filesDir

    $checkTopiaInstalled = checkTopiaInstalled
    "Topia Installed Object: " + $checkTopiaInstalled | Out-File -FilePath $logFile -Append
}
else {
    "vRx is already installed"  | out-file -FilePath $logFile

}
# confrim Unified is installed
start-sleep -s 10
$TopiaConn,$lastRegDate,$lastConErrDate = checkvRxConnection
if (($TopiaConn -eq "Registered") -or ($topiaConn -eq "NoErrors")){
    Write-host "vRx Registred at $lastRegDate"
    write-host "vRx Version: " $vRxInstall.DisplayVersion 
    "vRx Registred at $lastRegDate"  | Out-File -FilePath $logFile -Append 
    "vRx Is installed "+ $isTopiaInstalled.DisplayVersion | out-file -FilePath $logfile -append
}
else {
    Write-host "vRx Failed to register at $lastConErrDate"
    write-host "vRx Version: " $isTopiaInstalled.DisplayVersion 
    "vRx Failed to register at $lastConErrDate" | Out-File -FilePath $logFile -Append 
    "vRx Is installed "+ $isTopiaInstalled.DisplayVersion | out-file -FilePath $logfile -append
    start-sleep -s 60
    $TopiaConn,$lastRegDate,$lastConErrDate = checkvRxConnection
    if (($TopiaConn -eq "Registered") -or ($topiaConn -eq "NoErrors")){
        Write-host "vRx Registred at $lastRegDate"
        write-host "vRx Version: " $vRxInstall.DisplayVersion 
        "vRx Registred at $lastRegDate"  | Out-File -FilePath $logFile -Append 
        "vRx Is installed "+ $isTopiaInstalled.DisplayVersion | out-file -FilePath $logfile -append
    }
    else {
        Write-host "vRx Failed to register at $lastConErrDate"
        write-host "vRx Version: " $isTopiaInstalled.DisplayVersion 
        "vRx Failed to register at $lastConErrDate" | Out-File -FilePath $logFile -Append 
        "vRx Is installed "+ $isTopiaInstalled.DisplayVersion | out-file -FilePath $logfile -append
        if ($reinstallNotRegistered) {
            CleanupvRxf
            $argsList = New-Object PScustomObject
            if ($endpointTag) {
                $argsList | Add-Member -MemberType NoteProperty -Name "EndpointTag" -Value $endpointTag
            }
            if ($proxy) {
                $argsList | Add-Member -MemberType NoteProperty -Name "Proxy" -Value $Proxy
            }
            installvRx -secretKey $secretKey -hostname $hostname -argslist $argsList -logFile $logFile -filesdir $filesDir
        }
    }

}
$appsReg = @()
$appv4 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString,PSPath,PSParentPath | Where-object {$_.DisplayName -like "*Topia*"}
$appv5 = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,Publisher,DisplayVersion,UninstallString,PSPath,PSParentPath | Where-object {$_.DisplayName -like "*Topia*"}

$appsReg += $appv4
$appsReg += $appv5
$appsReg | export-csv "C:\Program Files\Vicarius\vRxUpgradeScript.csv" 
$appsReg
$ProgressPreference = $OriginalPref
} 
else {
    Write-host "OS is 32bit, Agent cannot be upgraded"
}
Stop-Transcript