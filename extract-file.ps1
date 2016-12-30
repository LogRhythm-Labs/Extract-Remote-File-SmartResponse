
  #====================================#
  # LogRhythm Security Operations      #
  # Extract Remote files and SCSM Logs #
  # greg . foss @ logrhythm . com      #
  # v0.1  --  December, 2016           #
  #====================================#

# Copyright 2016 LogRhythm Inc.   
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.

[CmdLetBinding()]
param( 
    [string]$target,
    [string]$username,
    [string]$password,
    [string]$file,
    [string]$location=".\"
)

#=======================================================================================
# Extract File from the Remote host
#=======================================================================================

try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }
    
    # Establish the Remote Session
    $session = New-PSSession -ComputerName $target -Credential $cred
    
    # Check the file - if related to SCSM, stop the agent before copying the file, restart after completion
    if ( $file -eq "scsm" ) {
        Invoke-Command -ScriptBlock { Stop-Service scsm } -ComputerName $target -Credential $cred
        cp "C:\Program Files\LogRhythm\LogRhythm System Monitor\logs\$file.log" "$location$target-$file.log" -FromSession $session
        Invoke-Command -ScriptBlock { Restart-Service scsm -Force } -ComputerName $target -Credential $cred
    } elseif ( $file -eq "filemon" ) {
        Invoke-Command -ScriptBlock { Stop-Service scsm } -ComputerName $target -Credential $cred
        cp "C:\Program Files\LogRhythm\LogRhythm System Monitor\logs\$file.log" "$location$target-$file.log" -FromSession $session
        Invoke-Command -ScriptBlock { Restart-Service scsm -Force } -ComputerName $target -Credential $cred
    } elseif ( $file -eq "regmon" ) {
        Invoke-Command -ScriptBlock { Stop-Service scsm } -ComputerName $target -Credential $cred
        cp "C:\Program Files\LogRhythm\LogRhythm System Monitor\logs\$file.log" "$location$target-$file.log" -FromSession $session
        Invoke-Command -ScriptBlock { Restart-Service scsm -Force } -ComputerName $target -Credential $cred
    } elseif ( $file -eq "rtfim" ) {
        Invoke-Command -ScriptBlock { Stop-Service scsm } -ComputerName $target -Credential $cred
        cp "C:\Program Files\LogRhythm\LogRhythm System Monitor\logs\$file.log" "$location$target-$file.log" -FromSession $session
        Invoke-Command -ScriptBlock { Restart-Service scsm -Force } -ComputerName $target -Credential $cred
    } else {
        
        # Extract Remote File
        try {
        $fileName = $file.split('\')[-1].split(' ')
        cp $file "$location$target-$fileName" -FromSession $session
        } catch {
            Write-Host "Nnnnoooooo....."
            Exit 1
        }
    }

} catch {
    Write-Host "Access Denied..."
    Exit 1
}

# Clean Up
Remove-PSSession $session
Clear-Variable target
Clear-Variable username
Clear-Variable password
Clear-Variable cred
Clear-Variable session
Clear-Variable file
Clear-Variable location


# SIG # Begin signature block
# MIIdxgYJKoZIhvcNAQcCoIIdtzCCHbMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpr2xOqvYg/844/JnleX736v0
# 8rygghi2MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTTMIIDu6ADAgECAhAY2tGeJn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHK
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsT
# FlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlT
# aWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZl
# cmlTaWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgLSBHNTAeFw0wNjExMDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl
# cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWdu
# LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT
# aWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgLSBHNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWe
# YAyq50s7Ttx8vDxFHLsr4P4pAvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3
# S7P+j34HV+zvQ9tmYhVhz2ANpNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ
# 2ENjalJL0o/ocFFN0Ylpe8dw9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE
# 75C55ADk3Tq1Gf8CuvQ87uCL6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6s
# KlLHj9UESeSNY0eIPGmDy/5HvSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80
# h5aK7lPoJRUCAwEAAaOBsjCBrzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
# AwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcG
# BSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJp
# c2lnbi5jb20vdnNsb2dvLmdpZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8z
# MTMwDQYJKoZIhvcNAQEFBQADggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSn
# oHgSrWIORXBkxeeXZi2YCX5fr9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjm
# BpFAGLn4we3f20Gq4JYgyc1kFTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpY
# T2DKfoJqCwKqJRc5tdt/54RlKpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh
# 9BFvELWV/OdCBTLbzp1RXii2noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2G
# dpxEevaVXPZdMggzpFS2GD9oXPJCSoU4VINf0egs8qwR1qjtY2owggU0MIIEHKAD
# AgECAhBvzqThCU6soC46iUEXOXVFMA0GCSqGSIb3DQEBBQUAMIG0MQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWdu
# IFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRwczov
# L3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTEwMS4wLAYDVQQDEyVWZXJpU2lnbiBD
# bGFzcyAzIENvZGUgU2lnbmluZyAyMDEwIENBMB4XDTE1MDQwOTAwMDAwMFoXDTE3
# MDQwMTIzNTk1OVowZjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRAw
# DgYDVQQHEwdCb3VsZGVyMRgwFgYDVQQKFA9Mb2dSaHl0aG0sIEluYy4xGDAWBgNV
# BAMUD0xvZ1JoeXRobSwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKwJYFWf7THEfBgk4pfEUtyGbYUnZmXxJVTTtyy5f0929hCAwuy09oEHpZqD
# uregBi0oZmGo+GJT7vF6W0PZCieXFzxyNfWqJxFb1mghKo+6aweDXWXEdpp/y38k
# /+iu9MiiOFVuJzKNxMD8F6iJ14kG64K+P9gNxIu2t4ajKRDKhN5V8dSDYqdjHlM6
# Vt2WcpqUR3E2LQXrls/aYmKe1Dg9Lf8R/0OeJPLQdnXuSIhBTTdrADmhwgh9F/Q5
# Wj0hS2rURWEIdn3HQsW5xJcHuYxh3YQUIIoDybY7ZolGrRNa1gKEEZVy3iMKoK28
# HEFkuBVGtVSqRed9um99XUU1udkCAwEAAaOCAY0wggGJMAkGA1UdEwQCMAAwDgYD
# VR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9zZi5zeW1jYi5j
# b20vc2YuY3JsMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUH
# AQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vc2Yuc3ltY2QuY29tMCYGCCsGAQUF
# BzAChhpodHRwOi8vc2Yuc3ltY2IuY29tL3NmLmNydDAfBgNVHSMEGDAWgBTPmanq
# eyb0S8mOj9fwBSbv49KnnTAdBgNVHQ4EFgQUoxV4rZFrQYUJv5kT9HiDLKNevs0w
# EQYJYIZIAYb4QgEBBAQDAgQQMBYGCisGAQQBgjcCARsECDAGAQEAAQH/MA0GCSqG
# SIb3DQEBBQUAA4IBAQDtr3hDFtDn6aOruSnJYX+0YqoWREkevcGwpM0bpuJvpCRo
# Fkl8PDobpukMNQdod3/4Iee+8ZRDObYAdKygL4LbLWlaG++wxPQJUXKurRgx/xrm
# SueNFE4oXPGkGG1m3Ffvp38MfUY3VR22z5riQmc4KF2WOTl2eJFiAKTRv31Wf46X
# V3TnMeSuJU+HGNQx1+XXYuK7vgZdyxRVftjbNSW26v/6PAv7slYyiOCvYvnSVCo4
# Kdc+zHj02Nm0IfGyuO+d+992+hEEnWk/WxLwjYXMs6hcHAmuFcfMNY0/mstdWq5/
# dlT/rOBNvFOpMshhwxT1Gl5FlpLzmdj/AbGaUPDSMIIGCjCCBPKgAwIBAgIQUgDl
# qiVW/BqG7ZbJ1EszxzANBgkqhkiG9w0BAQUFADCByjELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO
# ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBh
# dXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1
# YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMTAw
# MjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtDELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3
# b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNp
# Z24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2Rl
# IFNpZ25pbmcgMjAxMCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# APUjS16l14q7MunUV/fv5Mcmfq0ZmP6onX2U9jZrENd1gTB/BGh/yyt1Hs0dCIzf
# aZSnN6Oce4DgmeHuN01fzjsU7obU0PUnNbwlCzinjGOdF6MIpauw+81qYoJM1SHa
# G9nx44Q7iipPhVuQAU/Jp3YQfycDfL6ufn3B3fkFvBtInGnnwKQ8PEEAPt+W5cXk
# lHHWVQHHACZKQDy1oSapDKdtgI6QJXvPvz8c6y+W+uWHd8a1VrJ6O1QwUxvfYjT/
# HtH0WpMoheVMF05+W/2kk5l/383vpHXv7xX2R+f4GXLYLjQaprSnTH69u08MPVfx
# MNamNo7WgHbXGS6lzX40LYkCAwEAAaOCAf4wggH6MBIGA1UdEwEB/wQIMAYBAf8C
# AQAwcAYDVR0gBGkwZzBlBgtghkgBhvhFAQcXAzBWMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMCoGCCsGAQUFBwICMB4aHGh0dHBzOi8v
# d3d3LnZlcmlzaWduLmNvbS9ycGEwDgYDVR0PAQH/BAQDAgEGMG0GCCsGAQUFBwEM
# BGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFI/l0xqGrI2O
# a8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28u
# Z2lmMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Bj
# YTMtZzUuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AudmVyaXNpZ24uY29tMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItODAdBgNVHQ4E
# FgQUz5mp6nsm9EvJjo/X8AUm7+PSp50wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
# Qzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQADggEBAFYi5jSkxGHLSLkBrVaoZA/ZjJHE
# u8wM5a16oCJ/30c4Si1s0X9xGnzscKmx8E/kDwxT+hVe/nSYSSSFgSYckRRHsExj
# jLuhNNTGRegNhSZzA9CpjGRt3HGS5kUFYBVZUTn8WBRr/tSk7XlrCAxBcuc3IgYJ
# viPpP0SaHulhncyxkFz8PdKNrEI9ZTbUtD1AKI+bEM8jJsxLIMuQH12MTDTKPNjl
# N9ZvpSC9NOsm2a4N58Wa96G0IZEzb4boWLslfHQOWP51G2M/zjF8m48blp7FU3aE
# W5ytkfqs7ZO6XcghU8KCU2OvEg1QhxEbPVRSloosnD2SGgiaBS7Hk6VIkdMxggR6
# MIIEdgIBATCByTCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJ
# bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJU
# ZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykx
# MDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBD
# QQIQb86k4QlOrKAuOolBFzl1RTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQULW1Qrv+0nRLDT0er
# M0BiNm4hopcwDQYJKoZIhvcNAQEBBQAEggEAXsXVsOYnSjrXYjjtTKB8uuYi3dLL
# VTDX+hR8/dx28H24S2ZYNNvfLqPteEFWDzoBzgDBk3sxTpeNsPKCbUEriRRjExW+
# pFL+cNh/fyUxJEOcEZePLfM/IzSOSPeDc1eW4ceNKXNPmWLse085GGh57Xt654tQ
# +p6mjQCjUNZ2IL8AXewlQvTvR/DvbzBqXpW3E19s+IdXHb2YG1m1ZnnSNRXqeJL0
# akWLPMqbGqMt54JV5uLaTpbdDbBWT01tikMVe2XfbkS01e9Ocb3HwBVqy9sf+TR7
# 21XihitSY3s3iGD+CznuB3iPMEdCcwdN5uJybhSzwSQc2CWc6qJtHo9SQ6GCAgsw
# ggIHBgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGlt
# ZSBTdGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNjEyMzAyMzAyMDhaMCMGCSqGSIb3DQEJBDEWBBRRz/G5qSJc6simgf1H
# lbow08C2LDANBgkqhkiG9w0BAQEFAASCAQBuIUn6ZtNSos8mdHrWRJwl3VAfQ3qn
# lUon4whOZyrxVzssApFjlnsz9M9hpIwQQf7pVp6/PQq/EPFN91nMqRcbzkIo7zNB
# ZNsF5RZWy3jureYMcj74MQ9VZZBEcEOf+yt+94Yd0uq7FRjthuHuu4ithtRT3IIB
# pT5EHrEvpEArj7+DM70rDgrk42beSqegx5ErcDQ592MSiJP9f8TSNCn41hDMl1Lj
# jTx4GkP6Kp6ZRq9FtDHtXyB408WG4Nu1+lWNuzE+f3ydrxJVa2s9ce1htsT1FDNH
# Fpy4aUk4H4BMs9bBGfT8IRojeQb0jBF8trRow4jycUovmgTz3E0oXsr0
# SIG # End signature block
