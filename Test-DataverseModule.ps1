# Dataverse Module Test Script
# This script provides basic tests to verify the module functionality

Write-Host "Dataverse Module Test Script" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

# Test 1: Import Module
Write-Host "`n1. Testing Module Import..." -ForegroundColor Yellow
try {
    Import-Module $PSScriptRoot\Dataverse.psd1 -Force
    Write-Host "   ✓ Module imported successfully" -ForegroundColor Green
    
    # Show module info
    $moduleInfo = Get-Module Dataverse
    Write-Host "   Module Version: $($moduleInfo.Version)" -ForegroundColor Cyan
    Write-Host "   Module Path: $($moduleInfo.ModuleBase)" -ForegroundColor Cyan
}
catch {
    Write-Host "   ✗ Failed to import module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Check Functions
Write-Host "`n2. Testing Function Availability..." -ForegroundColor Yellow
$expectedFunctions = @(
    'Connect-PSDVOrg',
    'Update-PSDVAccessToken',
    'Invoke-PSDVWebRequest',
    'Read-PSDVTableData',
    'Get-PSDVTableDetail',
    'Get-PSDVTableColumn',
    'Get-PSDVTableItem',
    'Get-PSDVTableItemAuditHistory',
    'Get-PSDVTableItemChangeHistory',
    'New-PSDVTableItem',
    'Update-PSDVTableItem',
    'Remove-PSDVTableItem'
)

$availableFunctions = Get-Command -Module Dataverse | Select-Object -ExpandProperty Name
$missingFunctions = $expectedFunctions | Where-Object { $_ -notin $availableFunctions }

if ($missingFunctions.Count -eq 0) {
    Write-Host "   ✓ All expected functions are available ($($expectedFunctions.Count) functions)" -ForegroundColor Green
}
else {
    Write-Host "   ✗ Missing functions: $($missingFunctions -join ', ')" -ForegroundColor Red
}

# Test 3: Check Help Documentation
Write-Host "`n3. Testing Help Documentation..." -ForegroundColor Yellow
$functionsWithoutHelp = @()
foreach ($function in $expectedFunctions) {
    $help = Get-Help $function -ErrorAction SilentlyContinue
    if (-not $help -or $help.Synopsis -like "*$function*") {
        $functionsWithoutHelp += $function
    }
}

if ($functionsWithoutHelp.Count -eq 0) {
    Write-Host "   ✓ All functions have proper help documentation" -ForegroundColor Green
}
else {
    Write-Host "   ✗ Functions missing help: $($functionsWithoutHelp -join ', ')" -ForegroundColor Red
}

# Test 4: Check Aliases
Write-Host "`n4. Testing Aliases..." -ForegroundColor Yellow
$aliases = Get-Alias | Where-Object { $_.Definition -eq 'Remove-PSDVTableItem' }
if ($aliases) {
    Write-Host "   ✓ Backward compatibility alias found: $($aliases.Name)" -ForegroundColor Green
}
else {
    Write-Host "   ⚠ No backward compatibility aliases found" -ForegroundColor Yellow
}

# Test 5: Basic Parameter Validation
Write-Host "`n5. Testing Parameter Validation..." -ForegroundColor Yellow
try {
    # This should fail with proper error about missing connection
    Get-PSDVTableItem -Table "account" -ErrorAction Stop
    Write-Host "   ✗ Function should have failed without connection" -ForegroundColor Red
}
catch {
    if ($_.Exception.Message -like "*No existing connection*") {
        Write-Host "   ✓ Proper connection validation working" -ForegroundColor Green
    }
    else {
        Write-Host "   ⚠ Unexpected error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Test 6: Show Module Summary
Write-Host "`n6. Module Summary..." -ForegroundColor Yellow
$moduleInfo = Get-Module PSDataverse
Write-Host "   Module Name: $($moduleInfo.Name)" -ForegroundColor Cyan
Write-Host "   Version: $($moduleInfo.Version)" -ForegroundColor Cyan
Write-Host "   Author: $($moduleInfo.Author)" -ForegroundColor Cyan
Write-Host "   Description: $($moduleInfo.Description)" -ForegroundColor Cyan
Write-Host "   Exported Functions: $($moduleInfo.ExportedFunctions.Count)" -ForegroundColor Cyan
Write-Host "   Required Modules: $($moduleInfo.RequiredModules.Name -join ', ')" -ForegroundColor Cyan

Write-Host "`n==============================" -ForegroundColor Green
Write-Host "Module testing completed!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Install Az.Accounts module if not already installed:" -ForegroundColor White
Write-Host "   Install-Module Az.Accounts -MinimumVersion 3.0.0" -ForegroundColor Gray
Write-Host "2. Use Connect-PSDVOrg to establish a connection" -ForegroundColor White
Write-Host "3. Start using the module functions" -ForegroundColor White
Write-Host "`nFor detailed help on any function, use:" -ForegroundColor Yellow
Write-Host "   Get-Help <FunctionName> -Full" -ForegroundColor Gray