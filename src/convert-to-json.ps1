# Enhanced CSV to JSON/TXT Converter
param(
    [string]$Path,
    [string]$File,
    [switch]$Txt,
    [string]$Output
)

# Function to get user choice
function Get-UserChoice {
    param(
        [string]$Prompt,
        [string[]]$ValidChoices
    )
    
    do {
        $choice = Read-Host $Prompt
        if ($choice -in $ValidChoices) {
            return $choice
        }
        Write-Host "Invalid choice. Please try again." -ForegroundColor Red
    } while ($true)
}

# Function to convert CSV files
function Convert-CsvFiles {
    param(
        [string[]]$CsvFiles,
        [string]$OutputPath,
        [bool]$UseTxtExtension
    )
    
    $extension = if ($UseTxtExtension) { ".txt" } else { ".json" }
    $successCount = 0
    $failCount = 0
    
    Write-Host "Processing $($CsvFiles.Count) CSV files..." -ForegroundColor Cyan
    
    foreach ($csvPath in $CsvFiles) {
        if (-not (Test-Path $csvPath)) {
            Write-Warning "File does not exist: $csvPath"
            $failCount++
            continue
        }
        
        $csvFile = Get-Item $csvPath
        Write-Host "Converting: $($csvFile.Name)" -ForegroundColor Cyan
        
        try {
            # Determine output path
            if ($OutputPath) {
                $outputFile = Join-Path $OutputPath "$([System.IO.Path]::GetFileNameWithoutExtension($csvFile.Name))$extension"
            } else {
                $outputFile = $csvPath -replace '\.csv$', $extension
            }
            
            # Ensure output directory exists
            $outputDir = Split-Path $outputFile -Parent
            if (-not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }
            
            $csvData = Import-Csv -Path $csvPath
            $jsonContent = $csvData | ConvertTo-Json -Depth 10
            $jsonContent | Out-File -FilePath $outputFile -Encoding UTF8
            
            Write-Host "  Created: $([System.IO.Path]::GetFileName($outputFile))" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Warning "  Failed to convert $($csvFile.Name): $($_.Exception.Message)"
            $failCount++
        }
    }
    
    Write-Host "Conversion completed! Success: $successCount, Failed: $failCount" -ForegroundColor Green
}

# Main script logic
Write-Host "CSV to JSON/TXT Converter" -ForegroundColor Cyan

# Check if parameters were provided
if (-not $Path -and -not $File) {
    # Interactive mode
    Write-Host "`nNo parameters provided. Starting interactive mode..." -ForegroundColor Yellow
    
    # Ask user preference: folder or files
    Write-Host "`nWould you like to process a folder or files?"
    Write-Host "(1) Folder"
    Write-Host "(2) Files"
    $choice = Get-UserChoice -Prompt "Enter your choice (1 or 2)" -ValidChoices @("1", "2")
    
    if ($choice -eq "1") {
        # Folder processing
        do {
            $Path = Read-Host "`nPlease enter the folder path"
            if (-not (Test-Path $Path -PathType Container)) {
                Write-Host "Folder does not exist: $Path" -ForegroundColor Red
            }
        } while (-not (Test-Path $Path -PathType Container))
    }
    elseif ($choice -eq "2") {
        # File processing
        do {
            $File = Read-Host "`nPlease enter the path to each file separated by a comma"
            $fileList = $File -split "," | ForEach-Object { $_.Trim() }
            $allExist = $true
            foreach ($f in $fileList) {
                if (-not (Test-Path $f -PathType Leaf)) {
                    Write-Host "File does not exist: $f" -ForegroundColor Red
                    $allExist = $false
                }
            }
        } while (-not $allExist)
    }
    else {
        Write-Host "No valid option selected. Exiting script." -ForegroundColor Red
        exit 1
    }
    
    # Ask about output location
    $outputChoice = Get-UserChoice -Prompt "`nWould you like the output be next to the originating file? (Y/N)" -ValidChoices @("Y", "y", "N", "n")
    
    if ($outputChoice -in @("N", "n")) {
        do {
            $Output = Read-Host "What is the output path?"
            if (-not (Test-Path $Output -PathType Container)) {
                $createDir = Get-UserChoice -Prompt "Output directory does not exist. Create it? (Y/N)" -ValidChoices @("Y", "y", "N", "n")
                if ($createDir -in @("Y", "y")) {
                    try {
                        New-Item -ItemType Directory -Path $Output -Force | Out-Null
                        break
                    }
                    catch {
                        Write-Host "Failed to create directory: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                break
            }
        } while ($true)
    }
    
    # Ask about file extension
    $extChoice = Get-UserChoice -Prompt "`nWould you like .txt extension instead of .json? (Y/N)" -ValidChoices @("Y", "y", "N", "n")
    $Txt = $extChoice -in @("Y", "y")
}

# Validate parameters
if ($Path) {
    if (-not (Test-Path $Path -PathType Container)) {
        Write-Error "Folder does not exist: $Path"
        exit 1
    }
    
    $csvFiles = Get-ChildItem -Path $Path -Filter "*.csv" -File
    
    if ($csvFiles.Count -eq 0) {
        Write-Warning "No CSV files found in: $Path"
        exit 0
    }
    
    $csvFilePaths = $csvFiles | ForEach-Object { $_.FullName }
}
elseif ($File) {
    $csvFilePaths = $File -split "," | ForEach-Object { $_.Trim() }
    
    # Validate all files exist
    foreach ($csvPath in $csvFilePaths) {
        if (-not (Test-Path $csvPath -PathType Leaf)) {
            Write-Error "File does not exist: $csvPath"
            exit 1
        }
        if (-not $csvPath.EndsWith(".csv")) {
            Write-Warning "File does not appear to be a CSV: $csvPath"
        }
    }
}

# Validate output path if specified
if ($Output -and -not (Test-Path $Output -PathType Container)) {
    Write-Error "Output directory does not exist: $Output"
    exit 1
}

# Process the files
Convert-CsvFiles -CsvFiles $csvFilePaths -OutputPath $Output -UseTxtExtension $Txt 
