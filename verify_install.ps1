# Run BEFORE typing your password into an installed copy. $ExpectedThumbprint comes from the publisher through a separate trusted channel.
param([string]$Dir = "$env:ProgramFiles\UNKNWN", [Parameter(Mandatory)][string]$ExpectedThumbprint)
$s = Get-AuthenticodeSignature "$Dir\UNKNWN.exe"
if ($s.Status -ne "Valid" -or $s.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) { Write-Host "FAIL: not the expected signed release ($($s.Status))"; exit 1 }
if ($null -eq $s.TimeStamperCertificate) { Write-Host "WARNING: signature has no timestamp" }
Write-Host "Authenticode OK. Signer: $($s.SignerCertificate.Subject)"
