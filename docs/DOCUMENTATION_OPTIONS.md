# Obscura Documentation

This document outlines how to browse and contribute to the Obscura project documentation.

## Documentation with mdBook

**URL**: https://your-org.github.io/obscura/

**Description**: Documentation is built using [mdBook](https://rust-lang.github.io/mdBook/), a tool for creating online books from Markdown files, and deployed to GitHub Pages.

### Advantages of mdBook

- Clean, book-like navigation with table of contents
- Fast search functionality
- Mobile-friendly responsive design
- Code syntax highlighting
- Support for diagrams via mermaid integration
- Lightweight and fast loading
- Familiar to Rust developers
- Simple maintenance and contribution workflow

## How to Contribute to Documentation

All documentation is sourced from the `docs/` directory in the main repository. To contribute:

1. Fork the repository
2. Make changes to the relevant Markdown files in the `docs/` directory
3. Submit a pull request

The documentation will be automatically rebuilt and deployed when changes are merged to the main branch.

## Local Development

To preview documentation changes locally:

```bash
# Install mdBook
cargo install mdbook
cargo install mdbook-mermaid
cargo install mdbook-toc

# Create a book.toml file (copy from .mdbook/book.toml in the repo)
# Build and serve
mdbook serve
```

## Documentation Structure

The documentation is organized as follows:

- `docs/index.md`: Main entry point and overview
- `docs/architecture.md`: System architecture documentation
- `docs/consensus.md`: Consensus mechanism details
- `docs/development.md`: Development guide
- `docs/networking.md`: Network protocol documentation
- `docs/transactions.md`: Transaction format and processing
- `docs/mining_rewards/`: Mining rewards documentation
- And other specialized sections...

Please maintain this structure when adding new documentation. 