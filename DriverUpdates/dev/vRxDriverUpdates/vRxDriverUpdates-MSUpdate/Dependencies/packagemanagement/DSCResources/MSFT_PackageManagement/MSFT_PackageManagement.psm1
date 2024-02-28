#
# Copyright (c) Microsoft Corporation.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# This PS DSC resource enables installing a package. The resource uses Install-Package cmdlet
# to install the package from various providers/sources.

Import-LocalizedData -BindingVariable LocalizedData -filename MSFT_PackageManagement.strings.psd1

Import-Module -Name "$PSScriptRoot\..\PackageManagementDscUtilities.psm1"

function Get-TargetResource
{
    <#
    .SYNOPSIS

    This DSC resource provides a mechanism to download and install packages on a computer. 

    Get-TargetResource returns the current state of the resource.

    .PARAMETER Name
    Specifies the name of the Package to be installed or uninstalled.

    .PARAMETER Source
    Specifies the name of the package source where the package can be found.
    This can either be a URI or a source registered with Register-PackageSource cmdlet.
    The DSC resource MSFT_PackageManagementSource can also register a package source.
    
    .PARAMETER RequiredVersion
    Specifies the exact version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the newest available version of the package that also satisfies any
    maximum version specified by the MaximumVersion parameter.

    .PARAMETER MaximumVersion
    Specifies the maximum allowed version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the highest-numbered available version of the package.

    .PARAMETER MinimumVersion
    Specifies the minimum allowed version of the package that you want to install. If you do not add this parameter, 
    this DSC resource intalls the highest available version of the package that also satisfies any maximum 
    specified version specified by the MaximumVersion parameter.

    .PARAMETER SourceCredential
    Specifies a user account that has rights to install a package for a specified package provider or source.

    .PARAMETER ProviderName
    Specifies a package provider name to which to scope your package search. You can get package provider names 
    by running the Get-PackageProvider cmdlet.

    .PARAMETER AdditionalParameters
    Provider specific parameters that are passed as an Hashtable. For example, for NuGet provider you can
    pass additional parameters like DestinationPath.
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $RequiredVersion,
        
        [Parameter()]
        [System.String]
        $MinimumVersion,

        [Parameter()]
        [System.String]
        $MaximumVersion,

        [Parameter()]
        [System.String]
        $Source,

        [Parameter()]
        [PSCredential] $SourceCredential,

        [Parameter()]
        [System.String]
        $ProviderName,
        
        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]$AdditionalParameters        
    )
    
    $ensure = "Absent"
    $null = $PSBoundParameters.Remove("Source")
    $null = $PSBoundParameters.Remove("SourceCredential")

    if ($AdditionalParameters)
    {
         foreach($instance in $AdditionalParameters)
         {
             Write-Verbose ('AdditionalParameter: {0}, AdditionalParameterValue: {1}' -f $instance.Key, $instance.Value)
             $null = $PSBoundParameters.Add($instance.Key, $instance.Value)
         }
    }
    $null = $PSBoundParameters.Remove("AdditionalParameters")
    
    $verboseMessage =$localizedData.StartGetPackage -f (GetMessageFromParameterDictionary $PSBoundParameters),$env:PSModulePath
    Write-Verbose -Message $verboseMessage
    $result = PackageManagement\Get-Package @PSBoundParameters -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        

    if ($result.count -eq 1)
    {
        Write-Verbose -Message ($localizedData.PackageFound -f $Name)
        $ensure = "Present"
    }
    elseif ($result.count -gt 1)
    {
        Write-Verbose -Message ($localizedData.MultiplePackagesFound -f $Name)
        $ensure = "Present"
    }
    else
    {
        Write-Verbose -Message ($localizedData.PackageNotFound -f $($Name))
    }

    Write-Debug -Message "Source $($Name) is $($ensure)"
                         
    
    if ($ensure -eq 'Absent')
    {
        return @{
            Ensure       = $ensure
            Name         = $Name
            ProviderName = $ProviderName
            RequiredVersion = $RequiredVersion
            MinimumVersion = $MinimumVersion
            MaximumVersion = $MaximumVersion
        }
    }
    else
    {
        if ($result.Count -gt 1)
        {
          $result = $result[0]
        }

        return  @{
                Ensure             = $ensure
                Name               = $result.Name
                ProviderName       = $result.ProviderName
                Source             = $result.source
                RequiredVersion    = $result.Version
            } 
    } 
}

function Test-TargetResource
{
    <#
    .SYNOPSIS

    This DSC resource provides a mechanism to download and install packages on a computer. 

    Test-TargetResource returns a boolean which determines whether the resource is in
    desired state or not.

    .PARAMETER Name
    Specifies the name of the Package to be installed or uninstalled.

    .PARAMETER Source
    Specifies the name of the package source where the package can be found.
    This can either be a URI or a source registered with Register-PackageSource cmdlet.
    The DSC resource MSFT_PackageManagementSource can also register a package source.
    
    .PARAMETER RequiredVersion
    Specifies the exact version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the newest available version of the package that also satisfies any
    maximum version specified by the MaximumVersion parameter.

    .PARAMETER MaximumVersion
    Specifies the maximum allowed version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the highest-numbered available version of the package.

    .PARAMETER MinimumVersion
    Specifies the minimum allowed version of the package that you want to install. If you do not add this parameter, 
    this DSC resource intalls the highest available version of the package that also satisfies any maximum 
    specified version specified by the MaximumVersion parameter.

    .PARAMETER SourceCredential
    Specifies a user account that has rights to install a package for a specified package provider or source.

    .PARAMETER ProviderName
    Specifies a package provider name to which to scope your package search. You can get package provider names 
    by running the Get-PackageProvider cmdlet.

    .PARAMETER AdditionalParameters
    Provider specific parameters that are passed as an Hashtable. For example, for NuGet provider you can
    pass additional parameters like DestinationPath.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $RequiredVersion,
        
        [Parameter()]
        [System.String]
        $MinimumVersion,

        [Parameter()]
        [System.String]
        $MaximumVersion,

        [Parameter()]
        [System.String]
        $Source,

        [Parameter()]
        [PSCredential] $SourceCredential,
                
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure="Present",

        [Parameter()]
        [System.String]
        $ProviderName,
        
        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]$AdditionalParameters         
    )

    
    Write-Verbose -Message ($localizedData.StartTestPackage -f (GetMessageFromParameterDictionary $PSBoundParameters))
    $null = $PSBoundParameters.Remove("Ensure")
    
    $temp = Get-TargetResource @PSBoundParameters

    if ($temp.Ensure -eq $ensure)
    {
        Write-Verbose -Message ($localizedData.InDesiredState -f $Name, $Ensure, $temp.Ensure)            
        return $True 
    }
    else
    {
        Write-Verbose -Message ($localizedData.NotInDesiredState -f $Name,$ensure,$temp.ensure)            
        return [bool] $False
    }    
}

function Set-TargetResource
{
    <#
    .SYNOPSIS

    This DSC resource provides a mechanism to download and install packages on a computer. 

    Set-TargetResource either intalls or uninstall a package as defined by the vaule of Ensure parameter.

    .PARAMETER Name
    Specifies the name of the Package to be installed or uninstalled.

    .PARAMETER Source
    Specifies the name of the package source where the package can be found.
    This can either be a URI or a source registered with Register-PackageSource cmdlet.
    The DSC resource MSFT_PackageManagementSource can also register a package source.
    
    .PARAMETER RequiredVersion
    Specifies the exact version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the newest available version of the package that also satisfies any
    maximum version specified by the MaximumVersion parameter.

    .PARAMETER MaximumVersion
    Specifies the maximum allowed version of the package that you want to install. If you do not specify this parameter, 
    this DSC resource installs the highest-numbered available version of the package.

    .PARAMETER MinimumVersion
    Specifies the minimum allowed version of the package that you want to install. If you do not add this parameter, 
    this DSC resource intalls the highest available version of the package that also satisfies any maximum 
    specified version specified by the MaximumVersion parameter.

    .PARAMETER SourceCredential
    Specifies a user account that has rights to install a package for a specified package provider or source.

    .PARAMETER ProviderName
    Specifies a package provider name to which to scope your package search. You can get package provider names 
    by running the Get-PackageProvider cmdlet.

    .PARAMETER AdditionalParameters
    Provider specific parameters that are passed as an Hashtable. For example, for NuGet provider you can
    pass additional parameters like DestinationPath.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $RequiredVersion,
        
        [Parameter()]
        [System.String]
        $MinimumVersion,

        [Parameter()]
        [System.String]
        $MaximumVersion,

        [Parameter()]
        [System.String]
        $Source,

        [Parameter()]
        [PSCredential] $SourceCredential,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure="Present",

        [Parameter()]
        [System.String]
        $ProviderName,
        
        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]$AdditionalParameters        
    )

    Write-Verbose -Message ($localizedData.StartSetPackage -f (GetMessageFromParameterDictionary $PSBoundParameters))
    
    $null = $PSBoundParameters.Remove("Ensure")

    if ($PSBoundParameters.ContainsKey("SourceCredential"))
    {
        $PSBoundParameters.Add("Credential", $SourceCredential)
        $null = $PSBoundParameters.Remove("SourceCredential")
    }
    
    if ($AdditionalParameters)
    {
         foreach($instance in $AdditionalParameters)
         {
             Write-Verbose ('AdditionalParameter: {0}, AdditionalParameterValue: {1}' -f $instance.Key, $instance.Value)
             $null = $PSBoundParameters.Add($instance.Key, $instance.Value)
         }
    }

    $PSBoundParameters.Remove("AdditionalParameters")

       
        # We do not want others to control the behavior of ErrorAction
        # while calling Install-Package/Uninstall-Package.
        $PSBoundParameters.Remove("ErrorAction")
        if ($Ensure -eq "Present")
        {
            PackageManagement\Install-Package @PSBoundParameters -ErrorAction Stop
        }   
        else
        {
            # we dont source location for uninstalling an already
            # installed package
            $PSBoundParameters.Remove("Source")
            # Ensure is Absent
            PackageManagement\Uninstall-Package @PSBoundParameters -ErrorAction Stop
        }
 }
 
 function GetMessageFromParameterDictionary
 {
    <#
        Returns a strng of form "ParameterName:ParameterValue"
        Used with Write-Verbose message. The input is mostly $PSBoundParameters
    #>
    param([System.Collections.IDictionary] $paramDictionary)

    $returnValue = ""
    $paramDictionary.Keys | ForEach-Object { $returnValue += "-{0} {1} " -f $_,$paramDictionary[$_] }
    return $returnValue
 }

Export-ModuleMember -function Get-TargetResource, Set-TargetResource, Test-TargetResource


# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNHExVsaD0kyJT
# faO9Fdru5c5dZNw/I2f/WOIZwqnZQKCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg8R1Pmfow
# cdRZqYArE66BbwlcVzLXx5t2tD5hSPvyDEowQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBedem6Q3OYXCJBEmRWOHTGbwpF8jhgge13n0D0rin9
# vnhDSlqR4twFl4H5vCdM83akyPFsZaceMpZ0gKXH4mJDOWKaWsEA9qtmFHUjZYZs
# bytqIDtg8qqALBIph62aY60SYJZWGQmsLRgU5FGxJeR+85oxS9EGJeD8pr32CEsc
# 1iEYohcC8UrOYQofqRgOQYy02WQctkl35oyooAxkIHqQpb2pfu4zgxNw/YRcdPqJ
# 31feu1S/a+ZpBojIsdKPtIeX/42wiDSDMxslIvcitYwDnAW1et18CONrjvbSLcFT
# yeG2gZqgoYW034tWpk3qDrtE2yQimnJF9d0CP7ZFDmTkoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIMW7OuA6Nt2laJvbZYG2Or24ShzYgH3VTWUdvtx/
# NBRjAgZdQhNBJvIYEzIwMTkwODE2MjMyNTIyLjMxM1owBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAADwvF+brrNM/yUAAAAAAPAw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTgxMDI0MjExNDIyWhcNMjAwMTEwMjExNDIyWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlE
# REExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgNDVNasZyacqap9zBtsIEWmGWdkJx
# nMAI97MUGYXVAfpQrCVbM9YUX0yIokD+KcMkZ0ArB0B0RbhOI7q3EGfTHkRf2Ln3
# 9A9RZnVThRyczf0PqDYl/upaLQPXj1aR70GwjfMUYX6nEAIkrCvON2u/QFKhrIwn
# d1ViVq/tc56A1rKj0mFz0TcSk6T/AzDfOyLNHLeaxDhCIX9WPwpr6sZPv2D1ZbZA
# kSbthl5vUNYFdtxNx/haTCpo2FoH9fv4zJySfCncXJ/sy+kaBXVXtLT5j2gPQYGY
# cesf0BEj5X5IITTvlMVj1peVWs8CI5+YRPqNdZLGoIGY27WIM+i0NjGTAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQU26J6c6P3TjgxiTuSb4gD+ZYCTNEwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAbTLoGg593wQgWbkR6AkAX7ybv8N/EbxJXRXX99p2
# /4I3nsGcFaTKZKhDZ+DyzWWFNoOIJhrWxHrWvLSXsl0xilhpntb5oyhvwkXUYmr9
# 6hD7Q8wUT4d9Lu49PV/stCz0Br14iicOn6TCeLu8keiPQZ8PZeA3g+/eIgT8egry
# hv2m8i+qfowAbuEtHJIhH/MY3Jvo6sX2GNn5CUgLpmKnY1ceHoMchJAUb9qzP2fX
# knilmvBjNqPOukVrTz1hu3RyXNZ1edIL1xGaeCAK/Vgrk9wS5SXZIDvuJHbY9vqA
# igwc8Dk0XsHB1yiDTmcQUnawMDJjZttLBhXTavLiYp00rDCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYtOURE
# QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUADTYHhHELq8EAYxBiH4KhJQYLM7+ggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOEBqYkwIhgPMjAx
# OTA4MTcwNjE1MzdaGA8yMDE5MDgxODA2MTUzN1owdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4QGpiQIBADAKAgEAAgIWpwIB/zAHAgEAAgISBDAKAgUA4QL7CQIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAI0qB9wREMZNX3tIDQNgGziYthpccbkp
# nhaNmWBvdEsS50rC8q0uoRJFCfAAnzQexMBwczeQ9dGhLhTZJUifzzD7lmkhrhDk
# mITRwMStkPuo78KMqYyUkaHT5NxuX16NsYYaNE4JrS+RjL06h1W/aS64azivyBXQ
# wmLm/wpwGSJvMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAADwvF+brrNM/yUAAAAAAPAwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgIJsc1A63
# LB4AQ2biIIGBQ+v7Dnjh7X0qNa6omkpnCP4wgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCAM3kFp/S9Ebkh5zng8cKV03M2jYZcrfVf0y1QYlsYAkDCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAA8Lxfm66zTP8lAAAA
# AADwMCIEIBE27+VOQFbN5OXgmNZ7Ct0GeydD/hX4+LdDW25qvhKLMA0GCSqGSIb3
# DQEBCwUABIIBAF3LS6GFPxMkGHWXAm6unYLlTYogIqoq7+bowmjujXoLrNhDSDLZ
# iMbnloF2y3WQxhQLPHyxZgtkBSOXFG0V+yjTzOJBFTK2XeWg59xDzFOKi3uLeChv
# uq/dbbIpcsMEuyrtKIeIvgaU+Z9Gl7UiHcec+a3eacZFwOcPF0OiccLAr+TrddTm
# lPx2SlJ2cUanQwKOzehnJ/S9OrNO1nUJLODwSzS8dTpQBvGPn0rp1wHpdujaNH6y
# Yktu6sA23kqHSyWQ80zz7HjGFe593t7/61QOA7iGz5U2A2JNl6b1B4kOLFcWFgCd
# l3SnXwD2lP2jjPMeFhJbKvOcmSik0StphEQ=
# SIG # End signature block
