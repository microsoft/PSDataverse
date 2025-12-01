# PSDataverse Module Installation Script
# This script helps install the PSDataverse module to your PowerShell modules directory

param(
    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',
    
    [Parameter()]
    [switch]$Force
)

Write-Host "PSDataverse Module Installation Script" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

# Determine target path based on scope
if ($Scope -eq 'CurrentUser') {
    $targetPath = Join-Path $env:USERPROFILE "Documents\PowerShell\Modules\PSDataverse"
    Write-Host "Installing for current user..." -ForegroundColor Yellow
}
else {
    $targetPath = Join-Path $env:PROGRAMFILES "PowerShell\Modules\PSDataverse"
    Write-Host "Installing for all users (requires admin privileges)..." -ForegroundColor Yellow
}

Write-Host "Target installation path: $targetPath" -ForegroundColor Cyan

# Check if module already exists
if (Test-Path $targetPath) {
    if ($Force) {
        Write-Host "Removing existing module..." -ForegroundColor Yellow
        Remove-Item $targetPath -Recurse -Force
    }
    else {
        Write-Warning "Module already exists at $targetPath"
        $response = Read-Host "Do you want to overwrite it? (y/N)"
        if ($response -notlike 'y*') {
            Write-Host "Installation cancelled." -ForegroundColor Yellow
            exit 0
        }
        Remove-Item $targetPath -Recurse -Force
    }
}

# Create target directory
try {
    New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
    Write-Host "Created target directory." -ForegroundColor Green
}
catch {
    Write-Error "Failed to create target directory: $($_.Exception.Message)"
    exit 1
}

# Copy module files
try {
    $sourceFiles = @(
        "PSDataverse.psd1",
        "PSDataverse.psm1",
        "README.md",
        "Test-PSDataverseModule.ps1"
    )
    
    foreach ($file in $sourceFiles) {
        $sourcePath = Join-Path $PSScriptRoot $file
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $targetPath -Force
            Write-Host "Copied $file" -ForegroundColor Green
        }
        else {
            Write-Warning "Source file not found: $file"
        }
    }
}
catch {
    Write-Error "Failed to copy module files: $($_.Exception.Message)"
    exit 1
}

# Verify installation
try {
    Write-Host "`nVerifying installation..." -ForegroundColor Yellow
    Import-Module PSDataverse -Force
    $module = Get-Module PSDataverse
    
    if ($module) {
        Write-Host "✓ Module installed successfully!" -ForegroundColor Green
        Write-Host "  Version: $($module.Version)" -ForegroundColor Cyan
        Write-Host "  Path: $($module.ModuleBase)" -ForegroundColor Cyan
        Write-Host "  Functions: $($module.ExportedFunctions.Count)" -ForegroundColor Cyan
    }
    else {
        Write-Error "Module installation verification failed"
        exit 1
    }
}
catch {
    Write-Error "Failed to verify installation: $($_.Exception.Message)"
    exit 1
}

# Check prerequisites
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
$azAccounts = Get-Module Az.Accounts -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($azAccounts) {
    if ([version]$azAccounts.Version -ge [version]"3.0.0") {
        Write-Host "✓ Az.Accounts module found (version $($azAccounts.Version))" -ForegroundColor Green
    }
    else {
        Write-Warning "Az.Accounts version $($azAccounts.Version) found, but version 3.0.0 or later is required"
        Write-Host "To update: Update-Module Az.Accounts" -ForegroundColor Gray
    }
}
else {
    Write-Warning "Az.Accounts module not found"
    Write-Host "To install: Install-Module Az.Accounts -MinimumVersion 3.0.0" -ForegroundColor Gray
}

# Success message
Write-Host "`n======================================" -ForegroundColor Green
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Start a new PowerShell session or run: Import-Module PSDataverse" -ForegroundColor White
Write-Host "2. Use Get-Command -Module PSDataverse to see available functions" -ForegroundColor White
Write-Host "3. Use Get-Help Connect-PSDVOrg -Full to get started" -ForegroundColor White
Write-Host "4. Run the test script: .\Test-PSDataverseModule.ps1" -ForegroundColor White

Write-Host "`nModule is ready to use!" -ForegroundColor Green