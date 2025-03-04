@echo off
rem ====================================================================
rem Obscura Documentation Generator (Windows)
rem ====================================================================
rem This script generates comprehensive documentation for the project
rem including API docs and Jekyll-based user documentation.
rem
rem Requirements:
rem - Rust toolchain
rem - Jekyll (gem install jekyll bundler)
rem
rem Usage:
rem   scripts\docs.bat [--open] [--serve]
rem     Options:
rem       --open       Open generated documentation in browser
rem       --serve      Start Jekyll server for live preview
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Parse arguments
SET OPEN_DOCS=0
SET SERVE_DOCS=0

:parse_args
if "%1"=="" goto after_args
if "%1"=="--open" (
  SET OPEN_DOCS=1
  shift
  goto parse_args
)
if "%1"=="--serve" (
  SET SERVE_DOCS=1
  shift
  goto parse_args
)
shift
goto parse_args

:after_args

echo =====================================================================
echo             Generating Obscura Documentation                         
echo =====================================================================

rem Generate API documentation
echo Generating API documentation...
cargo doc --no-deps --all-features

rem Check if Jekyll is installed
jekyll -v >nul 2>&1
if errorlevel 1 (
  echo Jekyll not found. Please install Jekyll with: gem install jekyll bundler
  exit /b 1
)

rem Check for Jekyll site directory
if exist docs (
  echo Building Jekyll documentation...
  
  rem Navigate to the docs directory
  pushd docs
  
  rem If _api directory exists, copy API docs there
  if exist _api (
    echo Integrating API docs with Jekyll site...
    if not exist _api mkdir _api
    xcopy /E /Y ..\target\doc\* _api\
  )
  
  rem Build the Jekyll site
  if %SERVE_DOCS%==1 (
    echo Starting Jekyll server at http://localhost:4000
    rem Use bundle exec if Gemfile exists
    if exist Gemfile (
      bundle exec jekyll serve
    ) else (
      jekyll serve
    )
  ) else (
    rem Just build the site
    if exist Gemfile (
      bundle exec jekyll build
    ) else (
      jekyll build
    )
    
    echo Jekyll documentation generated successfully!
    echo - Jekyll Documentation: file:///%CD%/_site/index.html
    
    rem Go back to the project root
    popd
  )
) else (
  echo Jekyll docs directory not found. Only API documentation was generated.
)

echo - API Documentation: file:///%CD%/target/doc/obscura/index.html
  
rem Open documentation if requested
if %OPEN_DOCS%==1 if %SERVE_DOCS%==0 (
  echo Opening documentation in browser...
  if exist docs\_site (
    start "" "docs\_site\index.html"
  ) else (
    start "" "target\doc\obscura\index.html"
  )
)

rem Check documentation coverage
echo Checking documentation coverage...
cargo rustdoc -- -D warnings 