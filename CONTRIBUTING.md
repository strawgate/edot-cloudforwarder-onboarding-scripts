# Contributing to EDOT Discovery Tool

Thank you for your interest in contributing! This document outlines the requirements and process for getting your pull request merged.

## Requirements for Merging

All pull requests must meet the following criteria:

### 1. Code Quality

- [ ] All tests pass (`uv run pytest`)
- [ ] No linting errors (`uv run ruff check .`)
- [ ] No type errors (`uv run mypy src`)
- [ ] Code follows project style guidelines (see [CODE_STYLE.md](CODE_STYLE.md))

### 2. Test Coverage

- [ ] New features include tests
- [ ] Bug fixes include regression tests
- [ ] Coverage does not decrease

### 3. Documentation

- [ ] README updated if user-facing behavior changes
- [ ] Docstrings for new public functions
- [ ] DEVELOPING.md updated if development workflow changes

### 4. Security

- [ ] No secrets or credentials in code
- [ ] API keys and sensitive data are properly redacted in logs/output
- [ ] No shell injection vulnerabilities (use subprocess with `shell=False`)
- [ ] Dependencies pinned to avoid known vulnerabilities

### 5. Commit Standards

- [ ] Commits are atomic and focused
- [ ] Commit messages are clear and descriptive
- [ ] Branch is rebased on main (no merge commits)

## Pull Request Process

1. **Fork and Clone**: Fork the repository and clone locally
2. **Branch**: Create a feature branch from `main`
3. **Develop**: Make your changes following the style guide
4. **Test**: Run the full test suite locally
5. **Document**: Update documentation as needed
6. **Push**: Push your branch to your fork
7. **PR**: Open a pull request with a clear description

## PR Description Template

```markdown
## Summary

Brief description of what this PR does.

## Changes

- Change 1
- Change 2

## Testing

How was this tested?

## Checklist

- [ ] Tests pass
- [ ] Linting passes
- [ ] Documentation updated
```

## Getting Help

- Open an issue for bugs or feature requests
- Ask questions in PR comments
- See [DEVELOPING.md](DEVELOPING.md) for setup instructions

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build something useful together.
