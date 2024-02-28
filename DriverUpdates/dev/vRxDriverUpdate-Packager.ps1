#TopiaDriverUpdate Packager
$date = get-date -Format MM-dd-yyyy_mm-hh-ss 
$packageRootPath = "C:\Users\Jordan\Documents\GitHub\vRx-Scripts\DriverUpdates\dev"
$packageRootPathProd = "C:\Users\Jordan\Documents\GitHub\vRx-Scripts\DriverUpdates\prod"
#cd $packageRootPath\vRxDriverUpdates\TopiaDriverUpdates-MSUpdate
if (Test-Path "$packageRootPath\vRxDriverUpdates\vRxDriverUpdates-MSUpdate.zip") {
    $dest = "$packageRootPath\vRxDriverUpdates\old\vRxDriverUpdates-MSUpdate" + $date + ".zip"
    mv "$packageRootPath\vRxDriverUpdates\vRxDriverUpdates-MSUpdate.zip" $dest
}
$filesRootPath = "$packageRootPath\vRxDriverUpdates\vRxDriverUpdates-MSUpdate"
$compress = @{
    Path = "$filesRootPath\checkPendingRestart.ps1", "$filesRootPath\driverupdates-wup.ps1", "$filesRootPath\pswindowsupdate.2.2.0.3.nupkg", "$filesRootPath\Dependencies\"
    CompressionLevel = "Fastest"
    DestinationPath = "$packageRootPath\vRxDriverUpdates\vRxDriverUpdates-MSUpdate.zip" 
}
Compress-Archive @compress
$compress1 = @{
    Path = "$packageRootPath\vRxDriverUpdates\DriverUpdateLauncher.ps1", "$packageRootPath\vRxDriverUpdates\vRxDriverUpdates-MSUpdate.zip"
    CompressionLevel = "Fastest"
    DestinationPath = "$packageRootPath\vRxDriverUpdates.zip" 
}
if (Test-Path "$packageRootPath\vRxDriverUpdates.zip") {
    $dest = "$packageRootPath\vRxDriverUpdates\old\vRxDriverUpdates-"+ $date + ".zip"
    mv "$packageRootPath\vRxDriverUpdates.zip" $dest
}

if (Test-Path "$packageRootPathProd\vRxDriverUpdates.zip") {
    $dest = "$packageRootPathProd\old\vRxDriverUpdates-"+ $date + ".zip"
    mv "$packageRootPathProd\vRxDriverUpdates.zip" $dest
}
Compress-Archive @compress1
cp "$packageRootPath\vRxDriverUpdates.zip" "$packageRootPathProd\vRxDriverUpdates.zip"