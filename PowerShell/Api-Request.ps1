<#
.SYNOPSIS
    Skrypt sprawdza bezpieczeństwo pliku za pomocą VirusTotal API.

.DESCRIPTION
    Oblicza sumę kontrolną SHA256 pliku, wysyła zapytanie do VirusTotal, 
    interpretuje odpowiedź i wyświetla informację, czy plik jest bezpieczny.

.PARAMETER FilePath
    Pełna ścieżka do pliku, który ma zostać przeskanowany.

.PARAMETER ApiKey
    Klucz API do usługi VirusTotal.

.EXAMPLE
    .\Api-Request.ps1 -FilePath "C:\Test\eicar.com" -ApiKey "123abc..."
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

# [1] Obliczanie sumy kontrolnej SHA256
Write-Host "`n[1] Obliczanie sumy kontrolnej SHA256..."
if (Test-Path $FilePath) {
    $Sha256 = Get-FileHash -Path $FilePath -Algorithm SHA256
    $Hash = $Sha256.Hash
    Write-Host "Hash SHA256: $Hash"
} else {
    Write-Host "Plik nie istnieje: $FilePath"
    exit
}

# [2] Wysyłanie zapytania do API VirusTotal
Write-Host "`n[2] Wysyłanie zapytania do API VirusTotal..."
$Uri = "https://www.virustotal.com/api/v3/files/$Hash"

$Headers = @{
    "x-apikey" = $ApiKey
}

try {
    $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
} catch {
    Write-Host "Błąd podczas połączenia z VirusTotal: $_"
    exit
}

# [3] Interpretacja odpowiedzi
Write-Host "`n[3] Interpretacja odpowiedzi API..."

if ($Response.data.attributes.last_analysis_stats) {
    $Stats = $Response.data.attributes.last_analysis_stats
    $Malicious = $Stats.malicious
    $Suspicious = $Stats.suspicious
    $Harmless = $Stats.harmless
    $Undetected = $Stats.undetected

    Write-Host "Wyniki analizy:"
    Write-Host "  Złośliwe: $Malicious"
    Write-Host "  Podejrzane: $Suspicious"
    Write-Host "  Niezłośliwe: $Harmless"
    Write-Host "  Niewykryte: $Undetected"

    if ($Malicious -gt 0 -or $Suspicious -gt 0) {
        Write-Host "`n Plik jest potencjalnie NIEBEZPIECZNY!" 
    } else {
        Write-Host "`n Plik wygląda na BEZPIECZNY." 
    }
} else {
    Write-Host "Nie udało się uzyskać danych o analizie pliku."
}
