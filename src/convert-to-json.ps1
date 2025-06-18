# CSV to JSON Converter for AD Entitlement Review Output
# Converts all CSV files in the output folder to JSON format

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$ConfigPath,
    [switch]$PrettyFormat,
    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"

# Get script path
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== CSV to JSON Converter ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow

# Set config path if not provided
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptPath "..\configs"
}

# Load main configuration to get output folder
try {
    $configFile = Join-Path $ConfigPath "config.json"
    if (-not (Test-Path $configFile)) {
        throw "Configuration file not found: $configFile"
    }
    
    $configContent = Get-Content $configFile -Raw
    $config = ConvertFrom-Json $configContent
    Write-Host "Configuration loaded successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load configuration: $($_.Exception.Message)"
    exit 1
}

# Determine output path
if (-not $OutputPath) {
    $OutputPath = $config.OutputFolder
    if ($config.OutputFolder -match "^\.\.") {
        $OutputPath = Join-Path $scriptPath $config.OutputFolder
    }
}

# Validate output path exists
if (-not (Test-Path $OutputPath)) {
    Write-Error "Output path does not exist: $OutputPath"
    exit 1
}

Write-Host "Processing CSV files in: $OutputPath" -ForegroundColor Yellow

# Find all CSV files in the output directory
$csvFiles = Get-ChildItem -Path $OutputPath -Filter "*.csv" -File

if ($csvFiles.Count -eq 0) {
    Write-Warning "No CSV files found in: $OutputPath"
    exit 0
}

Write-Host "Found $($csvFiles.Count) CSV files to convert" -ForegroundColor Green

# Function to convert CSV data with proper type handling
function Convert-CsvToJson {
    param(
        [string]$CsvPath,
        [string]$JsonPath,
        [bool]$Pretty = $false
    )
    
    try {
        Write-Host "  Reading CSV data..." -ForegroundColor DarkGray
        $csvData = Import-Csv -Path $CsvPath
        
        if (-not $csvData -or $csvData.Count -eq 0) {
            Write-Warning "  CSV file is empty or contains no data"
            return $false
        }
        
        Write-Host "  Processing $($csvData.Count) records..." -ForegroundColor DarkGray
        
        # Convert data with proper type handling
        $processedData = @()
        foreach ($row in $csvData) {
            $processedRow = @{}
            
            foreach ($property in $row.PSObject.Properties) {
                $value = $property.Value
                $name = $property.Name
                
                # Handle common data types
                if ([string]::IsNullOrWhiteSpace($value)) {
                    $processedRow[$name] = $null
                }
                elseif ($value -eq "True" -or $value -eq "False") {
                    # Boolean values
                    $processedRow[$name] = [bool]::Parse($value)
                }
                elseif ($value -match "^\d+$") {
                    # Integer values
                    $processedRow[$name] = [int]$value
                }
                elseif ($value -match "^[\d\-]{8,10}T[\d\:]{8}") {
                    # DateTime values (ISO format)
                    try {
                        $processedRow[$name] = [DateTime]::Parse($value)
                    }
                    catch {
                        $processedRow[$name] = $value
                    }
                }
                elseif ($value -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") {
                    # GUID values - keep as string for JSON compatibility
                    $processedRow[$name] = $value
                }
                else {
                    # String values
                    $processedRow[$name] = $value
                }
            }
            
            $processedData += $processedRow
        }
        
        # Create JSON output with metadata
        $jsonOutput = @{
            metadata = @{
                sourceFile = Split-Path -Leaf $CsvPath
                generatedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                recordCount = $processedData.Count
                generatedBy = "AD Entitlement Review CSV to JSON Converter"
                version = "1.0"
            }
            data = $processedData
        }
        
        Write-Host "  Converting to JSON..." -ForegroundColor DarkGray
        
        if ($Pretty) {
            $jsonContent = $jsonOutput | ConvertTo-Json -Depth 10 -Compress:$false
        } else {
            $jsonContent = $jsonOutput | ConvertTo-Json -Depth 10 -Compress:$true
        }
        
        Write-Host "  Writing JSON file..." -ForegroundColor DarkGray
        $jsonContent | Out-File -FilePath $JsonPath -Encoding UTF8
        
        return $true
    }
    catch {
        Write-Error "  Failed to convert $CsvPath : $($_.Exception.Message)"
        return $false
    }
}

# Process each CSV file
$successCount = 0
$totalSize = 0

foreach ($csvFile in $csvFiles) {
    $csvPath = $csvFile.FullName
    $jsonFileName = [System.IO.Path]::ChangeExtension($csvFile.Name, ".json")
    $jsonPath = Join-Path $OutputPath $jsonFileName
    
    Write-Host "Converting: $($csvFile.Name)" -ForegroundColor Cyan
    
    # Check if JSON file already exists
    if ((Test-Path $jsonPath) -and -not $Overwrite) {
        Write-Warning "  JSON file already exists: $jsonFileName (use -Overwrite to replace)"
        continue
    }
    
    # Convert the file
    $success = Convert-CsvToJson -CsvPath $csvPath -JsonPath $jsonPath -Pretty $PrettyFormat
    
    if ($success) {
        $jsonFileInfo = Get-Item $jsonPath
        $csvFileInfo = Get-Item $csvPath
        
        $totalSize += $jsonFileInfo.Length
        $successCount++
        
        Write-Host "  ✓ Created: $jsonFileName" -ForegroundColor Green
        Write-Host "    CSV Size: $([math]::Round($csvFileInfo.Length / 1KB, 2)) KB" -ForegroundColor DarkGray
        Write-Host "    JSON Size: $([math]::Round($jsonFileInfo.Length / 1KB, 2)) KB" -ForegroundColor DarkGray
    }
    
    Write-Host ""
}

# Summary
Write-Host "=== Conversion Summary ===" -ForegroundColor Cyan
Write-Host "Files processed: $($csvFiles.Count)" -ForegroundColor Yellow
Write-Host "Successfully converted: $successCount" -ForegroundColor Green

if ($successCount -ne $csvFiles.Count) {
    Write-Host "Failed conversions: $($csvFiles.Count - $successCount)" -ForegroundColor Red
}

if ($totalSize -gt 0) {
    Write-Host "Total JSON size: $([math]::Round($totalSize / 1KB, 2)) KB" -ForegroundColor Yellow
}

Write-Host "JSON files saved to: $OutputPath" -ForegroundColor Yellow

if ($successCount -eq 0) {
    Write-Warning "No files were converted successfully"
    exit 1
} else {
    Write-Host "Conversion completed successfully!" -ForegroundColor Green
    exit 0
} 