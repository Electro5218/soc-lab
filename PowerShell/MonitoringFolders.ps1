<#
.SYNOPSIS
Monitoruje folder i przenosi pliki .txt do wskazanego miejsca.

.DESCRIPTION
Sprawdza co 2 sekundy folder źródłowy i przenosi wszystkie pliki .txt do folderu docelowego.
Jeśli folder docelowy nie istnieje, zostanie utworzony.

.PARAMETER SourcePath
Folder, który ma być monitorowany.

.PARAMETER DestinationPath
Folder, do którego mają być przenoszone pliki .txt.

.EXAMPLE
.\MonitoringFolders.ps1 -SourcePath "C:\In" -DestinationPath "C:\Out"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePath,

    [Parameter(Mandatory = $true)]
    [string]$DestinationPath
)

# Tworzenie folderu docelowego, jeśli nie istnieje
if (-not (Test-Path $DestinationPath)) {
    New-Item -ItemType Directory -Path $DestinationPath | Out-Null
    Write-Host "Utworzono folder docelowy: $DestinationPath"
}

Write-Host "`nStartuję monitoring folderu: $SourcePath"
Write-Host "Sprawdzam co 2 sekundy. Naciśnij Ctrl+C aby zakończyć.`n"

while ($true) {
    $files = Get-ChildItem -Path $SourcePath -Filter *.txt -File

    foreach ($file in $files) {
        $sourceFile = $file.FullName
        $destinationFile = Join-Path $DestinationPath $file.Name

        try {
            Move-Item -Path $sourceFile -Destination $destinationFile -Force
            Write-Host "Przeniesiono: $($file.Name)"
        } catch {
            Write-Host "Błąd przy przenoszeniu $($file.Name): $($_.Exception.Message)"
        }
    }

    Start-Sleep -Seconds 2
}
