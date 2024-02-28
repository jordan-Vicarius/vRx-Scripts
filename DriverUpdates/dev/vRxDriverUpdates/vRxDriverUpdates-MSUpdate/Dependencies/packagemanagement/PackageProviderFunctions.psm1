###
# ==++==
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###

<#
	Overrides the default Write-Debug so that the output gets routed back thru the
	$request.Debug() function
#>
function Write-Debug {
	param(
	[Parameter(Mandatory=$true)][string] $message,
	[parameter(ValueFromRemainingArguments=$true)]
	[object[]]
	 $args= @()
	)

	if( -not $request  ) {
		if( -not $args  ) {
			Microsoft.PowerShell.Utility\write-verbose $message
			return
		}

		$msg = [system.string]::format($message, $args)
		Microsoft.PowerShell.Utility\write-verbose $msg
		return
	}

	if( -not $args  ) {
		$null = $request.Debug($message);
		return
	}
	$null = $request.Debug($message,$args);
}

function Write-Error {
	param( 
		[Parameter(Mandatory=$true)][string] $Message,
		[Parameter()][string] $Category,
		[Parameter()][string] $ErrorId,
		[Parameter()][string] $TargetObject
	)

	$null = $request.Warning($Message);
}

<#
	Overrides the default Write-Verbose so that the output gets routed back thru the
	$request.Verbose() function
#>

function Write-Progress {
    param(
        [CmdletBinding()]

        [Parameter(Position=0)]
        [string]
        $Activity,

        # This parameter is not supported by request object
        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Status,

        [Parameter(Position=2)]
        [ValidateRange(0,[int]::MaxValue)]
        [int]
        $Id,

        [Parameter()]
        [int]
        $PercentComplete=-1,

        # This parameter is not supported by request object
        [Parameter()]
        [int]
        $SecondsRemaining=-1,

        # This parameter is not supported by request object
        [Parameter()]
        [string]
        $CurrentOperation,        

        [Parameter()]
        [ValidateRange(-1,[int]::MaxValue)]
        [int]
        $ParentID=-1,

        [Parameter()]
        [switch]
        $Completed,

        # This parameter is not supported by request object
        [Parameter()]
        [int]
        $SourceID,

	    [object[]]
        $args= @()
    )

    $params = @{}

    if ($PSBoundParameters.ContainsKey("Activity")) {
        $params.Add("Activity", $PSBoundParameters["Activity"])
    }

    if ($PSBoundParameters.ContainsKey("Status")) {
        $params.Add("Status", $PSBoundParameters["Status"])
    }

    if ($PSBoundParameters.ContainsKey("PercentComplete")) {
        $params.Add("PercentComplete", $PSBoundParameters["PercentComplete"])
    }

    if ($PSBoundParameters.ContainsKey("Id")) {
        $params.Add("Id", $PSBoundParameters["Id"])
    }

    if ($PSBoundParameters.ContainsKey("ParentID")) {
        $params.Add("ParentID", $PSBoundParameters["ParentID"])
    }

    if ($PSBoundParameters.ContainsKey("Completed")) {
        $params.Add("Completed", $PSBoundParameters["Completed"])
    }

	if( -not $request  ) {    
		if( -not $args  ) {
			Microsoft.PowerShell.Utility\Write-Progress @params
			return
		}

		$params["Activity"] = [system.string]::format($Activity, $args)
		Microsoft.PowerShell.Utility\Write-Progress @params
		return
	}

	if( -not $args  ) {
        $request.Progress($Activity, $Status, $Id, $PercentComplete, $SecondsRemaining, $CurrentOperation, $ParentID, $Completed)
	}

}

function Write-Verbose{
	param(
	[Parameter(Mandatory=$true)][string] $message,
	[parameter(ValueFromRemainingArguments=$true)]
	[object[]]
	 $args= @()
	)

	if( -not $request ) {
		if( -not $args ) {
			Microsoft.PowerShell.Utility\write-verbose $message
			return
		}

		$msg = [system.string]::format($message, $args)
		Microsoft.PowerShell.Utility\write-verbose $msg
		return
	}

	if( -not $args ) {
		$null = $request.Verbose($message);
		return
	}
	$null = $request.Verbose($message,$args);
}

<#
	Overrides the default Write-Warning so that the output gets routed back thru the
	$request.Warning() function
#>

function Write-Warning{
	param(
	[Parameter(Mandatory=$true)][string] $message,
	[parameter(ValueFromRemainingArguments=$true)]
	[object[]]
	 $args= @()
	)

	if( -not $request ) {
		if( -not $args ) {
			Microsoft.PowerShell.Utility\write-warning $message
			return
		}

		$msg = [system.string]::format($message, $args)
		Microsoft.PowerShell.Utility\write-warning $msg
		return
	}

	if( -not $args ) {
		$null = $request.Warning($message);
		return
	}
	$null = $request.Warning($message,$args);
}

<#
	Creates a new instance of a PackageSource object
#>
function New-PackageSource {
	param(
		[Parameter(Mandatory=$true)][string] $name,
		[Parameter(Mandatory=$true)][string] $location,
		[Parameter(Mandatory=$true)][bool] $trusted,
		[Parameter(Mandatory=$true)][bool] $registered,
		[bool] $valid = $false,
		[System.Collections.Hashtable] $details = $null
	)

	return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.PackageSource -ArgumentList $name,$location,$trusted,$registered,$valid,$details
}

<#
	Creates a new instance of a SoftwareIdentity object
#>
function New-SoftwareIdentity {
	param(
		[Parameter(Mandatory=$true)][string] $fastPackageReference,
		[Parameter(Mandatory=$true)][string] $name,
		[Parameter(Mandatory=$true)][string] $version,
		[Parameter(Mandatory=$true)][string] $versionScheme,
		[Parameter(Mandatory=$true)][string] $source,
		[string] $summary,
		[string] $searchKey = $null,
		[string] $fullPath = $null,
		[string] $filename = $null,
		[System.Collections.Hashtable] $details = $null,
		[System.Collections.ArrayList] $entities = $null,
		[System.Collections.ArrayList] $links = $null,
		[bool] $fromTrustedSource = $false,
		[System.Collections.ArrayList] $dependencies = $null,
		[string] $tagId = $null,
		[string] $culture = $null,
        [string] $destination = $null
	)
	return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity -ArgumentList $fastPackageReference, $name, $version,  $versionScheme,  $source,  $summary,  $searchKey, $fullPath, $filename , $details , $entities, $links, $fromTrustedSource, $dependencies, $tagId, $culture, $destination
}

<#
	Creates a new instance of a SoftwareIdentity object based on an xml string
#>
function New-SoftwareIdentityFromXml {
    param(
        [Parameter(Mandatory=$true)][string] $xmlSwidtag,
        [bool] $commitImmediately = $false
    )

    return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity -ArgumentList $xmlSwidtag, $commitImmediately
}

<#
	Creates a new instance of a DyamicOption object
#>
function New-DynamicOption {
	param(
		[Parameter(Mandatory=$true)][Microsoft.PackageManagement.MetaProvider.PowerShell.OptionCategory] $category,
		[Parameter(Mandatory=$true)][string] $name,
		[Parameter(Mandatory=$true)][Microsoft.PackageManagement.MetaProvider.PowerShell.OptionType] $expectedType,
		[Parameter(Mandatory=$true)][bool] $isRequired,
		[System.Collections.ArrayList] $permittedValues = $null
	)

	if( -not $permittedValues ) {
		return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.DynamicOption -ArgumentList $category,$name,  $expectedType, $isRequired
	}
	return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.DynamicOption -ArgumentList $category,$name,  $expectedType, $isRequired, $permittedValues.ToArray()
}

<#
	Creates a new instance of a Feature object
#>
function New-Feature {
	param(
		[Parameter(Mandatory=$true)][string] $name,
		[System.Collections.ArrayList] $values = $null
	)

	if( -not $values ) {
		return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.Feature -ArgumentList $name
	}
	return New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.Feature -ArgumentList $name, $values.ToArray()
}

<#
	Duplicates the $request object and overrides the client-supplied data with the specified values.
#>
function New-Request {
	param(
		[System.Collections.Hashtable] $options = $null,
		[System.Collections.ArrayList] $sources = $null,
		[PSCredential] $credential = $null
	)

	return $request.CloneRequest( $options, $sources, $credential )
}

function New-Entity {
	param(
		[Parameter(Mandatory=$true)][string] $name,
		[Parameter(Mandatory=$true,ParameterSetName="role")][string] $role,
		[Parameter(Mandatory=$true,ParameterSetName="roles")][System.Collections.ArrayList]$roles,
        [string] $regId = $null,
        [string] $thumbprint= $null
	)

	$o = New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.Entity
	$o.Name = $name

	# support role as a NMTOKENS string or an array of strings
	if( $role ) {
		$o.Role = $role
	} 
	if( $roles )  {
		$o.Roles = $roles
	}

	$o.regId = $regId
	$o.thumbprint = $thumbprint
	return $o
}

function New-Link {
	param(
		[Parameter(Mandatory=$true)][string] $HRef,
		[Parameter(Mandatory=$true)][string] $relationship,
		[string] $mediaType = $null,
		[string] $ownership = $null,
		[string] $use= $null,
		[string] $appliesToMedia= $null,
		[string] $artifact = $null
	)

	$o = New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.Link

	$o.HRef = $HRef
	$o.Relationship =$relationship
	$o.MediaType =$mediaType
	$o.Ownership =$ownership
	$o.Use = $use
	$o.AppliesToMedia = $appliesToMedia
	$o.Artifact = $artifact

	return $o
}

function New-Dependency {
	param(
		[Parameter(Mandatory=$true)][string] $providerName,
		[Parameter(Mandatory=$true)][string] $packageName,
		[string] $version= $null,
		[string] $source = $null,
		[string] $appliesTo = $null
	)

	$o = New-Object -TypeName Microsoft.PackageManagement.MetaProvider.PowerShell.Dependency

	$o.ProviderName = $providerName
	$o.PackageName =$packageName
	$o.Version =$version
	$o.Source =$source
	$o.AppliesTo = $appliesTo

	return $o
}
# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDs5FoY/w7B0Miq
# Kfi0Wb7Z3JGNbdfm1vY/fLsAXNclnKCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgW1aUJ//A
# XoZtrMMt6G72ZLxYaJSbe1y7/kqmNcIIh6wwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAoon9aywDgX0MhcHmwWJqgYX7Q//jyhdAhPKmZheTl
# K0rlPbuv1/MB8KLSSdKwgS/3uUlLvDTssCDFvEfwIJw5PJSVCAb8dF1KpYvFyc6j
# 1pYGELg5WOUN2lpuMaLi12FngvINKQcefy7TjIgoY86bq38a1wK2y64A8YWvf3Fl
# h3MSGDsS+2emxdb9bpmJnvNbYn200+zIhFup+vkVp73ocjkgbedarJ8bU+rD3hpJ
# iBHeuK/5s3MA1M9ydEEVvNf6rT3mHXzCyFaKnwzH9l0L79RC4GzUT6/Fpvz2cI48
# Rd4jKFqyvcmw7fj6UZQ96CMbptiQzkplMDK2J48TW7vioYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIJlawWI7jHUMRVRvl4gnonR6ZRb9xJsAOcWcLKVE
# X4aJAgZdQhWLC9cYEjIwMTkwODE2MjMyNTIyLjI4WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MUE4Ri1FM0MzLUQ2OUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2Wggg48MIIE8TCCA9mgAwIBAgITMwAAAPJ2DfwKMergIgAAAAAA8jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0x
# ODEwMjQyMTE0MjRaFw0yMDAxMTAyMTE0MjRaMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxQThGLUUzQzMtRDY5
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALYlr+mvw/bLN8BodJPfXW1bq2TM5g/t
# VFIYQMz8NhWK4/LSF0AzcAKNm3CbI5tOw7ZmGlDMC9U32Bh1fzTxH8cYLPLhWIV8
# 0gddFzG/oEnehainhq1z1yyPaye/Qw+sC+/rfEelKS7HUp41m2tcnk831Brqpjyi
# mfw68vA5PTxKbkMZlEEoM+3qwJHZKZhhuFFcWX5Ge142+Jc8z2vk5o7D+EGdv5hz
# KdiLVyTdAjFAMY3IaVY8bMKTTxJDs1PI3w1zTk6GS0BN9nYjWVWkdJ3wr15reNft
# Ts9BibtgfDLA128qPpXFET8pDkjMx7L+YFJ9CCY/p/OUR4iiS7OdWzsCAwEAAaOC
# ARswggEXMB0GA1UdDgQWBBS4/tw8WnSXg/JrywXuYexbkrFyyTAfBgNVHSMEGDAW
# gBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0Ff
# MjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEw
# LTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4IBAQCa9o0v2tms0rHwgF0t6PXcR8LkVR5l8g+NtO2Yv2Om
# 5IpDP2IuIyUEUWs3WX/PSpDS3Bvs6cCWJJKQO5f/fNylna5dv0UjNeF0L66KCliJ
# XGwxNHCbcWIqASm61GgeE/DbyXw3+FeK5OUqexcYRNL8u3ZZIJJV14vsUZUBRaJ6
# NrMNYCRJPNM3JRNI9fSxZFaGu9KW/GguyYBvqUqvYQTXvHMXSJsqdMiIupTFP2gD
# eBgowQY+ucJEwiuImpgtZZX5ogy+Tz6CQ+0eh+/3lVMOKQvytF8Tji0WcmplFn0l
# c5xvUAkgEQTtH+BPFKNqyEJKJPZL56ymTUp3X68FlewLMIIGcTCCBFmgAwIBAgIK
# YQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0
# NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX7
# 7XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM
# 1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHP
# k0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3Ws
# vYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw
# 6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHi
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVt
# VTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGS
# MIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4y
# IB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAu
# IB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+
# zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKK
# dsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/Uv
# eYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4z
# u2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
# bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlX
# dqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHh
# AN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A
# +xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdC
# osnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42ne
# V8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nf
# j950iEkSoYICzjCCAjcCAQEwgfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9w
# ZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjFBOEYtRTNDMy1ENjlE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQA2yWLDDSl8mq0I9vfNML4Rjbruo6CBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA4QGrzDAiGA8yMDE5
# MDgxNzA2MjUxNloYDzIwMTkwODE4MDYyNTE2WjB3MD0GCisGAQQBhFkKBAExLzAt
# MAoCBQDhAavMAgEAMAoCAQACAh5IAgH/MAcCAQACAhGjMAoCBQDhAv1MAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAUVSxmP2yyDAKNXHh9vLrsj6gYUAM+4YR
# h5FojnjrvagxqAIiIrub/gwZbb+jVlCI8HhVqL3iRjQYY2tP/V19HP/4OcYRjWik
# WOzaRvxhM+jJGt2kATTDpRlr+WAXaHJoJOOCS/BFJU0nTlpRYrWyai4jQH/WSzX/
# 7U7VVQrSKLYxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAPJ2DfwKMergIgAAAAAA8jANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDy9daA7vDV
# +QNMNaO1TcQ+nS8pJM7RNo7gSZKbuoKp4jCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIMmv9818fBA86rzxu2PyX4/9wwrjaRRPG0kwTE8LV1JFMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAADydg38CjHq4CIAAAAA
# APIwIgQgssV2pVkq8RWq0MPUz5sgfEGHG1mwSabtW/8aXgH697swDQYJKoZIhvcN
# AQELBQAEggEAKxfHS9VUNC9MfYqNBPWk3dLorERSxxt2xVvpxZd2DaczARGRr9y1
# vUVRz8pw5VN+AvL+ukAFQdAkHP/aGAtyHXuONQzFh9hIFxjrw2Iq7Y9K2wt1csaP
# ggPADf+v1RNefq8AriUxYbQ3DNsCfzY/jS2bOdfmx40vfkKQhpJLVHikDPA6OQpA
# ViOx84A9VCb7Fe/l8q5DLXN3Lh6CmMHrd2xEqDI9hqgEb6e6yIRpo75joX84V+k2
# Nt/CZTuMddPIxfjDhHnT+C4wU/RMW2LeO8ppewRoJ5HyJxdEsB3m2t4sqvX23se2
# 0lGewpk7KnUqjD3JSPB91icxSLgKiFC0fQ==
# SIG # End signature block
