---
layout: page
title: Documentation Quick Reference
parent: Reference Guides
nav_order: 2
---

# Documentation Quick Reference

This quick reference guide provides commonly used commands and solutions for working with Obscura's documentation system.

## Common Commands

| Task | Unix Command | Windows Command |
|------|-------------|----------------|
| Generate documentation | `./scripts/docs.sh` | `scripts\docs.bat` |
| Generate and view docs | `./scripts/docs.sh --open` | `scripts\docs.bat --open` |
| Start live preview server | `./scripts/docs.sh --serve` | `scripts\docs.bat --serve` |

## Documentation Locations

| Documentation Type | Location |
|-------------------|----------|
| API Documentation | `target/doc/obscura/` |
| Jekyll Documentation | `docs/_site/` |
| Integrated API Docs | `docs/_api/` |

## Common Jekyll Commands

If you need more control over the Jekyll documentation process:

```bash
# Navigate to the docs directory
cd docs

# Build the site
bundle exec jekyll build

# Start the preview server
bundle exec jekyll serve

# Build with detailed output
bundle exec jekyll build --verbose
```

## Linking to API Documentation

When integrating API docs with Jekyll pages, use relative paths:

```markdown
Check the [`MyStruct`]({% raw %}{{ site.baseurl }}{% endraw %}/_api/obscura/struct.MyStruct.html) documentation 
for more details.
```

## Fixing Documentation Coverage Issues

If the documentation coverage check fails:

1. Look for missing documentation in your Rust code
2. Ensure all public items have documentation comments
3. Fix any invalid doc comments (incorrect links, formatting errors)
4. Add missing `#[doc(hidden)]` attributes for items that shouldn't be documented

Example of properly documented Rust code:

```rust
/// Represents a transaction in the Obscura blockchain.
///
/// # Examples
///
/// ```
/// let tx = Transaction::new();
/// ```
pub struct Transaction {
    // Fields...
}

impl Transaction {
    /// Creates a new transaction with default values.
    ///
    /// # Returns
    ///
    /// A new [`Transaction`] instance.
    pub fn new() -> Self {
        // Implementation...
    }
}
```

## Common Jekyll Front Matter

Template for new documentation pages:

```yaml
---
layout: page
title: Your Page Title
parent: Parent Section Title
nav_order: 1
---

# Your Page Title

Content goes here...
``` 