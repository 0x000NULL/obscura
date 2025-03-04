---
layout: page
title: Documentation Generator
parent: Development Scripts
nav_order: 3
---

# Documentation Generator

The Obscura project includes specialized scripts that generate comprehensive documentation, combining API references with user guides.

## Features

- **API Documentation**: Automatically generated from code comments using Rust's documentation system
- **User Documentation**: Built with Jekyll, supporting auto-build on git push
- **Integration**: Option to integrate API documentation within the Jekyll site
- **Live Preview**: Development server with hot reloading for documentation changes

## Requirements

Before using these scripts, ensure you have:

- **Rust Toolchain**: For API documentation generation
- **Jekyll**: For building the user documentation
  ```
  gem install jekyll bundler
  ```

## Usage

### Basic Documentation Generation

To generate both API and Jekyll documentation:

**Unix:**
```bash
./scripts/docs.sh
```

**Windows:**
```cmd
scripts\docs.bat
```

### View Documentation in Browser

To generate documentation and open it in your default browser:

**Unix:**
```bash
./scripts/docs.sh --open
```

**Windows:**
```cmd
scripts\docs.bat --open
```

### Development Mode with Live Preview

To start a Jekyll server that provides live preview as you edit documentation:

**Unix:**
```bash
./scripts/docs.sh --serve
```

**Windows:**
```cmd
scripts\docs.bat --serve
```

The development server runs at [http://localhost:4000](http://localhost:4000).

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--open` | Opens the generated documentation in your default browser |
| `--serve` | Starts a Jekyll server for live preview |

## How It Works

1. **API Documentation** is generated from code comments and stored in `target/doc/`
2. **Jekyll Documentation** is built from the content in the `docs/` directory
3. If a `docs/_api` directory exists, API docs are copied there to enable integration with the Jekyll site

## Directory Structure

```
project-root/
├── docs/                 # Jekyll documentation directory
│   ├── _api/             # Optional directory for API docs integration
│   ├── _site/            # Generated Jekyll site (after build)
│   └── Gemfile           # Optional Ruby dependencies file
└── target/
    └── doc/              # Generated API documentation
```

## Adding API Documentation to Jekyll

To integrate API documentation with your Jekyll site:

1. Create a directory named `_api` in your docs folder
2. Run the documentation generation script
3. The script will automatically copy API documentation into this directory
4. Create links to API documentation in your Jekyll pages using relative paths

## Troubleshooting

### Jekyll Not Found

If you see the error "Jekyll not found", install Jekyll:

```bash
gem install jekyll bundler
```

### API Documentation Not Appearing in Jekyll Site

Ensure you have created a `docs/_api` directory. The script will copy API docs there automatically.

### Documentation Coverage Warnings

The script runs a documentation coverage check that treats warnings as errors. If the build fails with documentation warnings, you'll need to fix the documentation in your Rust code. 