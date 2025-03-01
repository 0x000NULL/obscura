# Contributing to Obscura

Thank you for your interest in contributing to the Obscura blockchain project! This guide will help you understand how to contribute to the project effectively.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](code_of_conduct.md). Please read it before contributing.

## How to Contribute

There are many ways to contribute to Obscura:

1. **Reporting Bugs**: If you find a bug, please report it by creating an issue in our GitHub repository.
2. **Suggesting Enhancements**: If you have ideas for new features or improvements, please create an issue to discuss them.
3. **Contributing Code**: If you want to contribute code, please follow the process outlined below.
4. **Improving Documentation**: Help us improve our documentation by fixing errors, adding examples, or clarifying explanations.
5. **Reviewing Pull Requests**: Help review pull requests from other contributors.

## Development Workflow

### Setting Up Your Development Environment

1. **Fork the Repository**: Fork the Obscura repository to your GitHub account.
2. **Clone Your Fork**: Clone your fork to your local machine.
   ```
   git clone https://github.com/your-username/obscura.git
   cd obscura
   ```
3. **Set Up Remote**: Add the original repository as a remote to keep your fork in sync.
   ```
   git remote add upstream https://github.com/obscura/obscura.git
   ```
4. **Install Dependencies**: Install the required dependencies.
   ```
   cargo build
   ```

### Making Changes

1. **Create a Branch**: Create a new branch for your changes.
   ```
   git checkout -b feature/your-feature-name
   ```
2. **Make Your Changes**: Make your changes to the codebase.
3. **Write Tests**: Write tests for your changes to ensure they work correctly.
4. **Run Tests**: Run the tests to make sure they pass.
   ```
   cargo test
   ```
5. **Format Your Code**: Format your code using the project's formatting guidelines.
   ```
   cargo fmt
   ```
6. **Lint Your Code**: Lint your code to ensure it meets the project's coding standards.
   ```
   cargo clippy
   ```

### Submitting Changes

1. **Commit Your Changes**: Commit your changes with a clear and descriptive commit message.
   ```
   git commit -m "Add feature: your feature description"
   ```
2. **Push Your Changes**: Push your changes to your fork.
   ```
   git push origin feature/your-feature-name
   ```
3. **Create a Pull Request**: Create a pull request from your fork to the original repository.
4. **Describe Your Changes**: In the pull request description, explain what your changes do and why they should be included.
5. **Address Review Comments**: Address any comments or feedback from the reviewers.

## Pull Request Guidelines

- **One Feature Per Pull Request**: Keep your pull requests focused on a single feature or bug fix.
- **Clear Description**: Provide a clear description of what your pull request does.
- **Include Tests**: Include tests for your changes.
- **Update Documentation**: Update the documentation to reflect your changes.
- **Follow Coding Standards**: Follow the project's coding standards and style guidelines.
- **Sign Your Commits**: Sign your commits to verify that you are the author of the changes.

## Reporting Bugs

When reporting bugs, please include:

1. **Steps to Reproduce**: Clear steps to reproduce the bug.
2. **Expected Behavior**: What you expected to happen.
3. **Actual Behavior**: What actually happened.
4. **Environment**: Information about your environment (OS, Rust version, etc.).
5. **Additional Information**: Any additional information that might be helpful.

## Security Vulnerabilities

If you discover a security vulnerability, please do NOT open an issue. Instead, email security@obscura.io with details about the vulnerability. We will work with you to address the issue promptly.

## Documentation Contributions

Improving documentation is a valuable contribution. To contribute to the documentation:

1. **Fork and Clone**: Fork and clone the repository as described above.
2. **Make Changes**: Make your changes to the documentation files in the `docs` directory.
3. **Build Documentation**: Build the documentation to make sure it renders correctly.
   ```
   cd docs
   mdbook build
   ```
4. **Submit a Pull Request**: Submit a pull request with your changes.

## Community

Join our community to discuss the project, ask questions, and get help:

- **Discord**: [Join our Discord server](https://discord.gg/obscura)
- **Forum**: [Visit our forum](https://forum.obscura.io)
- **Twitter**: [Follow us on Twitter](https://twitter.com/obscurachain)

## License

By contributing to Obscura, you agree that your contributions will be licensed under the project's license.

## Testing Requirements

Obscura maintains a high standard of code quality and test coverage. All contributions must include appropriate tests:

### Test Coverage Expectations

1. **New Features**: Must include comprehensive tests covering all code paths
2. **Bug Fixes**: Must include regression tests that would have caught the bug
3. **Refactoring**: Must maintain or improve existing test coverage
4. **Documentation**: No tests required, but examples should be verified

### Testing Best Practices

Please follow our [Testing Best Practices](testing/testing_best_practices.md) when writing tests. Key points include:

1. **Test Structure**: Follow the Arrange-Act-Assert pattern
2. **Naming Conventions**: Use descriptive test names that indicate what is being tested
3. **Mock Dependencies**: Use mocking to isolate the component being tested
4. **Test Both Success and Error Paths**: Ensure all code paths are tested

### Running Tests

Before submitting a pull request, ensure all tests pass:

```bash
# Run all tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo test -- --nocapture

# Check test coverage (requires cargo-tarpaulin)
cargo tarpaulin
```

### Test Review

During code review, we will evaluate your tests for:

1. **Correctness**: Tests should accurately verify expected behavior
2. **Completeness**: Tests should cover all relevant code paths
3. **Clarity**: Tests should be understandable and well-documented
4. **Performance**: Tests should run efficiently 