@echo off
REM Script to format Rust code according to project standards

echo Formatting Rust code with rustfmt...
cargo fmt --all

echo Checking code with clippy...
cargo clippy -- -D warnings

echo Done! Code is now formatted according to project standards.
echo Remember to commit your changes. 