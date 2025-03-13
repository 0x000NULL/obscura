# Cross-compilation script for Obscura
Write-Host "Building Obscura for multiple platforms..."

# Create output directory if it doesn't exist
$outputDir = "target/cross-compiled"
New-Item -ItemType Directory -Force -Path $outputDir

# Windows Build (native)
Write-Host "Building for Windows..."
cargo build --release
Copy-Item "target/release/obscura.exe" -Destination "$outputDir/obscura-windows.exe"

# Linux Build
Write-Host "Building for Linux..."
cargo build --release --target x86_64-unknown-linux-gnu
Copy-Item "target/x86_64-unknown-linux-gnu/release/obscura" -Destination "$outputDir/obscura-linux"

# macOS Build
Write-Host "Building for macOS..."
cargo build --release --target x86_64-apple-darwin
Copy-Item "target/x86_64-apple-darwin/release/obscura" -Destination "$outputDir/obscura-macos"

Write-Host "Cross-compilation complete! Binaries are in $outputDir" 