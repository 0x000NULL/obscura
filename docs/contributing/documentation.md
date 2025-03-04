---
layout: page
title: Documentation Guidelines
parent: Contributing
nav_order: 3
---

# Contributing to Documentation

Obscura uses a Jekyll-based documentation system that integrates with API documentation generated from the codebase. This guide will help you understand how to contribute to the project documentation.

## Documentation Structure

The Obscura documentation is organized as follows:

- **API Documentation**: Generated from code comments using Rust's documentation tools
- **User Documentation**: Written in Markdown and built with Jekyll
- **Integration**: API documentation can be accessed from within the Jekyll site

## Setting Up Your Environment

To work with the documentation locally, you'll need:

1. **Rust Toolchain**: For API documentation generation
2. **Ruby**: For running Jekyll (version 2.5.0 or newer)
3. **Bundler and Jekyll**: For building the documentation site

```bash
# Install bundler and jekyll
gem install bundler jekyll

# Navigate to the docs directory
cd docs

# Install dependencies from the Gemfile
bundle install
```

## Using the Documentation Scripts

Obscura provides convenience scripts for working with documentation:

```bash
# Generate all documentation
./scripts/docs.sh

# Generate and open documentation in browser
./scripts/docs.sh --open

# Start a development server with live preview
./scripts/docs.sh --serve
```

## Writing User Documentation

User documentation is written in Markdown and processed by Jekyll:

1. Create or edit files in the `docs/` directory
2. Use Markdown for formatting with Jekyll front matter at the top of each file
3. Organize content using Jekyll's navigation structure

### Jekyll Front Matter

Every Markdown file should begin with front matter:

```yaml
---
layout: page
title: Your Page Title
parent: Parent Section Name
nav_order: 1
---
```

### Documentation Best Practices

- Use clear, concise language
- Include code examples where appropriate
- Provide step-by-step instructions for complex procedures
- Use screenshots for UI features
- Link to related documentation
- Include troubleshooting sections for common issues

## Documenting Code

API documentation is generated from Rust doc comments:

```rust
/// This function does something important.
///
/// # Examples
///
/// ```
/// let result = my_function();
/// assert!(result.is_ok());
/// ```
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn my_function() -> Result<(), Error> {
    // Implementation...
}
```

### Documentation Comments Best Practices

- Document all public items (functions, structs, enums, etc.)
- Include examples in doc comments
- Explain parameters and return values
- Document error conditions and panics
- Link to related functions and types with `[`link`]` syntax
- Use markdown formatting in doc comments

## Adding API Documentation to Jekyll

To integrate API documentation with the Jekyll site:

1. Ensure the `docs/_api` directory exists
2. Run the documentation generator script
3. Reference API docs in your Jekyll pages with relative links

Example link to API documentation:

```markdown
See the [`Transaction`]({% raw %}{{ site.baseurl }}{% endraw %}/_api/obscura/struct.Transaction.html) documentation for details.
```

## Building for Production

Documentation is automatically built and deployed when changes are pushed to the repository. The Jekyll site will be built and hosted according to the repository configuration.

## Testing Documentation Changes

Before submitting a pull request:

1. Generate the documentation locally
2. Preview the documentation using the development server
3. Check for broken links and formatting issues
4. Ensure API documentation is correctly integrated
5. Verify that all code examples are correct and up-to-date 