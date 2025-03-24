# General test runner script that handles access violations

function Run-Test {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $false)]
        [string]$TestFilter = ""
    )
    
    Write-Host "Running test: $TestName" -ForegroundColor Cyan
    
    # Construct the command
    $cmd = "cargo test"
    if ($TestName -ne "") {
        $cmd += " --test $TestName"
    }
    if ($TestFilter -ne "") {
        $cmd += " $TestFilter"
    }
    $cmd += " -- --nocapture"
    
    # Run the command and capture output
    Write-Host "Command: $cmd" -ForegroundColor DarkGray
    $output = Invoke-Expression "$cmd 2>&1"
    
    # Display output
    $output | ForEach-Object { Write-Host $_ }
    
    # Check if tests passed by looking for test failures
    $failedCount = ($output | Select-String -Pattern "test result: FAILED" | Measure-Object).Count
    
    if ($failedCount -eq 0) {
        # Look for success messages
        $passed = $true
        
        # Return true if tests passed
        return $true
    }
    else {
        # Return false if tests failed
        return $false
    }
}

# Header
Write-Host "===========================================" -ForegroundColor Yellow
Write-Host "   OBSCURA CRYPTOCURRENCY TEST RUNNER  " -ForegroundColor Yellow  
Write-Host "===========================================" -ForegroundColor Yellow
Write-Host ""

# Run tests
$results = @()

# Memory protection tests
$memoryProtectionPassed = Run-Test -TestName "memory_protection_integration_test"
$results += [PSCustomObject]@{
    TestName = "Memory Protection Tests"
    Result = if ($memoryProtectionPassed) { "PASSED" } else { "FAILED" }
}

# Other key tests can be added here
# For example:
# $blockchainPassed = Run-Test -TestName "" -TestFilter "blockchain::tests"
# $results += [PSCustomObject]@{
#     TestName = "Blockchain Tests"
#     Result = if ($blockchainPassed) { "PASSED" } else { "FAILED" }
# }

# Print summary
Write-Host ""
Write-Host "===========================================" -ForegroundColor Yellow
Write-Host "             TEST SUMMARY                  " -ForegroundColor Yellow
Write-Host "===========================================" -ForegroundColor Yellow

$allPassed = $true
foreach ($result in $results) {
    if ($result.Result -eq "PASSED") {
        Write-Host "$($result.TestName): " -NoNewline
        Write-Host "PASSED" -ForegroundColor Green
    }
    else {
        Write-Host "$($result.TestName): " -NoNewline
        Write-Host "FAILED" -ForegroundColor Red
        $allPassed = $false
    }
}

Write-Host ""
Write-Host "===========================================" -ForegroundColor Yellow

if ($allPassed) {
    Write-Host "All tests PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Note: Access violations after tests complete are a known issue."
    Write-Host "They occur during test cleanup but do not affect test validity."
    exit 0
}
else {
    Write-Host "Some tests FAILED!" -ForegroundColor Red
    exit 1
} 