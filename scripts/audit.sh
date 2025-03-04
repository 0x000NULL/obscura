#!/bin/bash

# ====================================================================
# Obscura Dependency Audit Script (Unix)
# ====================================================================
# This script checks dependencies for security vulnerabilities, outdated
# packages, and generates dependency reports.
#
# Requirements:
# - Rust toolchain
# - cargo-audit (cargo install cargo-audit)
# - cargo-outdated (cargo install cargo-outdated)
# - cargo-lichking (cargo install cargo-lichking) (optional)
#
# Usage:
#   ./scripts/audit.sh [options]
#     Options:
#       --fix        Apply automatic fixes when possible
#       --report     Generate detailed HTML report
# ====================================================================

# Ensure we run from the root of the project
cd "$(dirname "$0")/.." || exit

# Process arguments
FIX_MODE=0
REPORT_MODE=0

for arg in "$@"; do
  case $arg in
    --fix)
      FIX_MODE=1
      ;;
    --report)
      REPORT_MODE=1
      ;;
  esac
done

echo "====================================================================="
echo "                Obscura Dependency Audit                             "
echo "====================================================================="

# Check for required tools
if ! command -v cargo-audit &> /dev/null; then
  echo "cargo-audit not found. Installing..."
  cargo install cargo-audit
fi

if ! command -v cargo-outdated &> /dev/null; then
  echo "cargo-outdated not found. Installing..."
  cargo install cargo-outdated
fi

# Create reports directory
if [ $REPORT_MODE -eq 1 ]; then
  mkdir -p reports
fi

# Check for security vulnerabilities
echo "Checking for security vulnerabilities..."
if [ $FIX_MODE -eq 1 ]; then
  AUDIT_COMMAND="cargo audit fix"
else
  AUDIT_COMMAND="cargo audit"
fi

if [ $REPORT_MODE -eq 1 ]; then
  $AUDIT_COMMAND --format json > reports/security_audit.json
  echo "Security audit report saved to reports/security_audit.json"
else
  $AUDIT_COMMAND
fi

# Check for outdated dependencies
echo -e "\nChecking for outdated dependencies..."
OUTDATED_COMMAND="cargo outdated"

if [ $REPORT_MODE -eq 1 ]; then
  $OUTDATED_COMMAND --format json > reports/outdated_dependencies.json
  echo "Outdated dependencies report saved to reports/outdated_dependencies.json"
else
  $OUTDATED_COMMAND
fi

# Check dependency licenses
echo -e "\nChecking dependency licenses..."
if command -v cargo-lichking &> /dev/null; then
  if [ $REPORT_MODE -eq 1 ]; then
    cargo lichking > reports/license_check.txt
    echo "License check report saved to reports/license_check.txt"
  else
    cargo lichking
  fi
else
  echo "cargo-lichking not installed. Skipping license check."
  echo "To enable license checking, run: cargo install cargo-lichking"
fi

# Generate dependency tree
echo -e "\nGenerating dependency tree..."
if [ $REPORT_MODE -eq 1 ]; then
  cargo tree --all > reports/dependency_tree.txt
  echo "Dependency tree saved to reports/dependency_tree.txt"
else
  cargo tree
fi

# Generate HTML report if requested
if [ $REPORT_MODE -eq 1 ]; then
  echo -e "\nGenerating HTML report..."
  
  # Create simple HTML report
  cat > reports/dependencies_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Obscura Dependency Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333366; }
        h2 { color: #336699; margin-top: 20px; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .vulnerability { color: #cc0000; }
        .outdated { color: #ff6600; }
        .ok { color: #008800; }
    </style>
</head>
<body>
    <h1>Obscura Dependency Audit Report</h1>
    <p>Generated on $(date)</p>
    
    <h2>Security Vulnerabilities</h2>
    <pre>$(cat reports/security_audit.json)</pre>
    
    <h2>Outdated Dependencies</h2>
    <pre>$(cat reports/outdated_dependencies.json)</pre>
    
    <h2>License Check</h2>
    <pre>$(cat reports/license_check.txt 2>/dev/null || echo "License check not available")</pre>
    
    <h2>Dependency Tree</h2>
    <pre>$(cat reports/dependency_tree.txt)</pre>
</body>
</html>
EOF

  echo "HTML report generated at reports/dependencies_report.html"
fi

echo -e "\nDependency audit complete!" 