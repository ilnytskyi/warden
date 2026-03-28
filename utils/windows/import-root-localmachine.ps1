param(
    [Parameter(Mandatory = $true)]
    [string]$CertificatePath,

    [Parameter(Mandatory = $true)]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true)]
    [string]$StatusPath
)

$ErrorActionPreference = 'Stop'

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
} catch [System.Security.Cryptography.CryptographicException] {
    if ($_.Exception.Message -match 'Access is denied') {
        Set-Content -Path $StatusPath -Value 'access_denied' -NoNewline
        exit 1
    }
    if ($_.Exception.Message -match 'group policy|policy|administrator has blocked|managed by your organization') {
        Set-Content -Path $StatusPath -Value 'policy_blocked' -NoNewline
        exit 1
    }
    Set-Content -Path $StatusPath -Value 'store_error' -NoNewline
    exit 1
}

try {
    try {
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
        if (-not $existing) {
            $staleWardenRoots = @(
                $store.Certificates | Where-Object {
                    $_.Thumbprint -ne $Thumbprint -and
                    $_.Subject -like '*O=Warden.dev*' -and
                    $_.Subject -like '*CN=Warden Proxy Local CA*'
                }
            )

            $store.Add($cert)

            foreach ($staleCert in $staleWardenRoots) {
                $store.Remove($staleCert)
            }
        }
    } catch [System.Security.Cryptography.CryptographicException] {
        if ($_.Exception.Message -match 'group policy|policy|administrator has blocked|managed by your organization') {
            Set-Content -Path $StatusPath -Value 'policy_blocked' -NoNewline
        } else {
            Set-Content -Path $StatusPath -Value 'store_error' -NoNewline
        }
        exit 1
    } catch {
        Set-Content -Path $StatusPath -Value 'store_error' -NoNewline
        exit 1
    }
} finally {
    $store.Close()
}

Set-Content -Path $StatusPath -Value 'imported' -NoNewline
