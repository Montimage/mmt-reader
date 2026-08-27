# Contributing to MMT-Reader

Thank you for your interest in MMT-Reader! This document outlines how to contribute to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Build Verification](#build-verification)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

---

## Reporting Bugs

Before filing a bug report:

1. **Search existing issues** — Check if the bug has already been reported.
2. **Gather information** — Collect the following:
   - MMT-Reader version (`mmtReader --version` → `mmtReader version:`)
   - MMT-DPI SDK version (`mmtReader --version` → `MMT-DPI SDK version:`)
   - Operating system and architecture
   - The exact command used
   - A sample pcap file that reproduces the issue (if possible)
   - Full output including any error messages

3. **File an issue** — Use the GitHub issue tracker with the template below:

```
**Version:** MMT-Reader 0.4.0, MMT-DPI <version>
**OS:** Linux x86_64
**Command:** ./mmtReader analyze -t capture.pcap -a

**Expected behavior:**
...

**Actual behavior:**
...

**Steps to reproduce:**
1. ...
2. ...
3. ...

**Attachments:**
- capture.pcap (if available)
- Full output log
```

---

## Suggesting Features

Feature requests are welcome. Please include:

- A clear description of the desired feature
- Use case(s) that justify the feature
- Any suggested implementation approach
- Whether you're willing to implement it yourself

---

## Submitting Changes

1. **Fork the repository**
2. **Create a feature branch** — `git checkout -b feature/my-feature`
3. **Make your changes** — Follow the [code style](#code-style) guidelines
4. **Commit your changes** — Use clear, descriptive commit messages
5. **Test your changes** — Run the [build verification](#build-verification) steps
6. **Push to your fork** — `git push origin feature/my-feature`
7. **Open a Pull Request** — Provide a description of your changes

### Pull Request Checklist

- [ ] Changes compile without warnings (`make` builds with `-Wall -Wextra`)
- [ ] Changes produce correct output with test pcap
- [ ] New features are documented in `docs/USER_GUIDE.md`
- [ ] Changelog entry added in `docs/CHANGELOG.md`
- [ ] No new dependencies without prior discussion

---

## Code Style

MMT-Reader is a modular C application (see `docs/ARCHITECTURE.md`). Please follow these conventions:

### Naming

- **Functions:** `snake_case` — e.g., `parseOptions()`, `packet_handler()`
- **Variables:** `snake_case` — e.g., `nb_packets`, `mmt_handler`
- **Macros:** `UPPER_SNAKE_CASE` — e.g., `MAX_FILENAME_SIZE`, `TRACE_FILE`
- **Global variables:** prefixed with descriptive names — e.g., `nb_ipv4_sessions`

### Formatting

- 4-space indentation (no tabs)
- Opening braces on the same line as control statements
- Blank line between function definitions
- Maximum line length: 120 characters

### Error Handling

- Use `fprintf(stderr, ...)` for error messages
- Exit with `exit(0)` for fatal errors in CLI tools
- Return `EXIT_FAILURE` / `EXIT_SUCCESS` from `main()`

### Comments

- Document function purpose, parameters, and return values
- Use `/** ... */` for public-facing functions
- Use `//` for inline comments

---

## Build Verification

Before submitting a PR, verify your changes:

```bash
# 1. Build — warnings are enabled by default (WARNFLAGS = -Wall -Wextra)
#    and the build must stay warning-free
make clean && make

# 2. Run the full test suite
make test

# 3. Test with offline mode
./mmtReader analyze -t smallFlows.pcap -a

# 4. Test with online mode (requires root and an interface)
sudo ./mmtReader capture -i eth0 -a
# Press Ctrl+C to stop

# 5. Verify help output
./mmtReader -h

# 6. Check for memory leaks (if valgrind is available)
valgrind --leak-check=full ./mmtReader analyze -t smallFlows.pcap -a
```

---

## Contact

For questions or issues, contact the maintainers at: **contact@montimage.com**
