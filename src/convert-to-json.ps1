# Simple CSV to JSON Converter
param(
    [string]$Path = ".\output"
)

Write-Host "Converting CSV files to JSON..." -ForegroundColor Cyan
Write-Host "Source path: $Path" -ForegroundColor Yellow

if (-not (Test-Path $Path)) {
    Write-Error "Path does not exist: $Path"
    exit 1
}

$csvFiles = Get-ChildItem -Path $Path -Filter "*.csv" -File

if ($csvFiles.Count -eq 0) {
    Write-Warning "No CSV files found in: $Path"
    exit 0
}

Write-Host "Found $($csvFiles.Count) CSV files" -ForegroundColor Green

foreach ($csvFile in $csvFiles) {
    $csvPath = $csvFile.FullName
    $jsonPath = $csvPath -replace '\.csv$', '.json'
    
    Write-Host "Converting: $($csvFile.Name)" -ForegroundColor Cyan
    
    try {
        $csvData = Import-Csv -Path $csvPath
        $jsonContent = $csvData | ConvertTo-Json -Depth 10
        $jsonContent | Out-File -FilePath $jsonPath -Encoding UTF8
        
        Write-Host "  Created: $([System.IO.Path]::GetFileName($jsonPath))" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Failed to convert $($csvFile.Name): $($_.Exception.Message)"
    }
}

Write-Host "Conversion completed!" -ForegroundColor Green 
