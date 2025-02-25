# Obscura Documentation Options

This document outlines the different options available for browsing the Obscura project documentation.

## Available Documentation Options

We provide multiple ways to browse the Obscura documentation, each with its own advantages and disadvantages:

### 1. GitHub Pages with mdBook

**URL**: https://your-org.github.io/obscura/docs/

**Description**: Documentation is built using [mdBook](https://rust-lang.github.io/mdBook/), a tool for creating online books from Markdown files, and deployed to GitHub Pages.

**Pros**:
- Clean, book-like navigation with table of contents
- Fast search functionality
- Mobile-friendly responsive design
- Code syntax highlighting
- Support for diagrams via mermaid integration
- Lightweight and fast loading
- Familiar to Rust developers

**Cons**:
- Limited customization options compared to full documentation frameworks
- Basic theming capabilities
- No versioning support out of the box

### 2. GitHub Wiki

**URL**: https://github.com/your-org/obscura/wiki

**Description**: Documentation is synced to the GitHub Wiki associated with the repository.

**Pros**:
- Integrated directly with GitHub
- Easy to edit directly through GitHub's interface
- No additional build process required
- Familiar to GitHub users
- Supports Markdown

**Cons**:
- Limited formatting options
- Basic navigation
- No versioning support
- Limited search capabilities
- No support for complex layouts or interactive elements

### 3. Docusaurus

**URL**: https://your-org.github.io/obscura/docusaurus/

**Description**: Documentation is built using [Docusaurus](https://docusaurus.io/), a modern static website generator focused on documentation sites.

**Pros**:
- Feature-rich documentation platform
- Advanced search functionality
- Versioning support
- Customizable themes and layouts
- Support for React components for interactive documentation
- Blog functionality
- Internationalization support
- Strong community and plugin ecosystem

**Cons**:
- More complex setup
- Requires JavaScript knowledge for advanced customization
- Heavier than simpler solutions like mdBook
- Requires Node.js ecosystem

## Recommended Option

**Our recommendation**: GitHub Pages with mdBook

For the Obscura project, we recommend using mdBook deployed to GitHub Pages as the primary documentation solution. This recommendation is based on:

1. **Alignment with the Rust ecosystem**: Since Obscura is built with Rust, mdBook provides a familiar documentation format for potential contributors.
2. **Simplicity and performance**: mdBook offers a clean, fast, and straightforward documentation experience without unnecessary complexity.
3. **Sufficient features**: For our current documentation needs, mdBook provides all the necessary features including search, navigation, and code highlighting.
4. **Low maintenance**: The mdBook setup requires minimal maintenance while providing a good user experience.

As the project grows, we may consider migrating to Docusaurus if we need more advanced features like versioning, internationalization, or interactive documentation components.

## How to Contribute to Documentation

Regardless of which browsing option you prefer, all documentation is sourced from the `docs/` directory in the main repository. To contribute:

1. Fork the repository
2. Make changes to the relevant Markdown files in the `docs/` directory
3. Submit a pull request

The documentation will be automatically rebuilt and deployed when changes are merged to the main branch.

## Local Development

To preview documentation changes locally:

### mdBook

```bash
# Install mdBook
cargo install mdbook
cargo install mdbook-mermaid
cargo install mdbook-toc

# Create a book.toml file (copy from .mdbook/book.toml in the repo)
# Build and serve
mdbook serve
```

### Docusaurus

```bash
# Navigate to the docusaurus directory
cd docusaurus

# Install dependencies
npm install

# Start development server
npm start
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