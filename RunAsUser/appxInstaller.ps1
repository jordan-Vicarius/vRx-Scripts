#Install Dependencies 
$date = get-date -Format dd-MM-yyyy-HH:mm:ss
$logpath = "C:\Program Files\Vicarius\vRxappXInstaller"
$rootPath = "C:\Program Files\Vicarius\temp\Packages\"
if (!(test-path -Path $rootPath)) {
    mkdir $rootPath
}   
$date + $logpath + " Installing Dependecies " 

$OriginalPref = $ProgressPreference # Default is 'Continue'
$ProgressPreference = "SilentlyContinue"
$tlsver = [Net.ServicePointManager]::SecurityProtocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function InstallRunAsDependencies {
    function DownloadDependencies {
        $nugetURL = "https://github.com/jordan-Vicarius/psModules/releases/download/nuget-2.8.5.208/Microsoft.PackageManagement.NuGetProvider.dll"
        $nugetPath = "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208"
        if (!(test-path -Path $nugetPath)) {
            mkdir $nugetPath
        }
        $nugetDLL = "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"
        if (!(test-path -Path $nugetDLL)) {
            invoke-webrequest $nugetURL -OutFile $nugetDLL
        }

    }
    function DownloadRunAsUser {
        $RunAsuserURL = "https://github.com/jordan-Vicarius/psModules/releases/download/RunAsuser/runasuser.2.4.0.nupkg"
        $RunAsUserPath = "$rootPath\runasuser.2.4.0.nupkg"
        if (!(test-path -Path $RunAsUserPath)) {
            invoke-webrequest $RunAsuserURL -OutFile $RunAsUserPath
        }

    }
    $installedPackProviderNuget = $false
    function installNuget {
        Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208
        Install-PackageProvider -name NuGet
        $installedPackProviderNuget = $true
    }
    function RegisterPSREPO{
        $repoName = "PSUpdateLocal"
        Register-PSRepository -Name $repoName -SourceLocation "$rootPath\" -PublishLocation "$rootPath\" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
    function installRunAsUser{
        $repoName = "PSUpdateLocal"
        install-module -name RunAsUser -Repository $repoName -ErrorAction SilentlyContinue
        import-module -Name RunAsUser 
    }
    #Check if Nuget is installed
    if (!(test-path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll")) {
        DownloadDependencies
        installNuget
        #Check if RunAsUser is installed

    }
    else {
        write-host "Nuget is already installed"
    }
    if (!(test-path -Path "$rootPath\runasuser.2.4.0.nupkg")) {
        DownloadRunAsUser
    }
    RegisterPSREPO
    installRunAsUser

    

}

function uninstallRunAsDep {
    $repoName = "PSUpdateLocal"
    Unregister-PSRepository -Name $repoName 
    remove-module -name RunAsUser -Force -ErrorAction SilentlyContinue
    remove-module -name PowershellGet
    remove-module -name PackageManagement
    uninstall-module -name RunAsUser -Force
}
# Installs Depdendencies for RunAsUser Module 
## NugetProvider ## RunAsuser Module
## Installs a local repo for modules 
InstallRunAsDependencies


# Install application 
# Download url for executable/msi/appx/appxbundle/msix/msixbundle

$url = ""

$ApplicationName = "" # Name including the extension

if (!(test-path "C:\temp\")){
    mkdir "C:\temp\"
}
if (Test-Path "C:\temp\$ApplicationName") {
    Remove-Item "C:\temp\$ApplicationName"
}
invoke-webrequest $url -OutFile "C:\temp\$ApplicationName"

$scriptblock = {
    #APPX Package installation
    $params = @{
        Path = "C:\temp\$applicationName"
        DeferRegistrationWhenPackagesAreInUse = $true
    }
    Add-AppxPackage @params

    #MSI Package installation
    #$Path = "C:\temp\$applicationName"
    
    #Start-Process -FilePath msiexec -ArgumentList "/i $Path /qn /norestart" -Wait -PassThru 

    #executable installation
    #$Path = "C:\temp\$applicationName"
    #Start-Process -FilePath "$path" -Wait -PassThru
}
try{
Invoke-AsCurrentUser -scriptblock $scriptblock
} catch{
write-error "Something went wrong"
}
uninstallRunAsDep
$ProgressPreference = $OriginalPref
[Net.ServicePointManager]::SecurityProtocol = $tlsver