# Contributing to DIRO

Thank you for considering contributing to DIRO! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Follow ethical hacking principles
- Report security vulnerabilities responsibly
- Ensure all contributions are legal and ethical

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version)
   - Error messages or logs

### Suggesting Features

1. Check existing feature requests
2. Create an issue with:
   - Clear description of the feature
   - Use cases and benefits
   - Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/YourFeature
   ```

3. Make your changes following these guidelines:
   - Write clear, commented code
   - Follow PEP 8 style guide for Python
   - Add docstrings to functions and classes
   - Test your changes thoroughly

4. Commit your changes:
   ```bash
   git commit -m "Add: Brief description of changes"
   ```
   Use prefixes: `Add:`, `Fix:`, `Update:`, `Remove:`

5. Push to your fork:
   ```bash
   git push origin feature/YourFeature
   ```

6. Create a Pull Request with:
   - Clear title and description
   - Reference related issues
   - Screenshots/demos if applicable

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/diro.git
cd diro

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Make changes and test
python3 diro.py
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and modular
- Maximum line length: 100 characters

Example:
```python
def scan_port(host, port, timeout=1):
    """
    Scan a single port on the target host.
    
    Args:
        host (str): Target IP address or hostname
        port (int): Port number to scan
        timeout (int): Connection timeout in seconds
    
    Returns:
        bool: True if port is open, False otherwise
    """
    # Implementation here
```

## Testing

- Test your changes on Kali Linux if possible
- Verify features work with both Python 3.6+ and latest version
- Test error handling and edge cases
- Ensure existing functionality is not broken

## Module Development

When adding new modules:

1. Create a class for the module
2. Use static methods where appropriate
3. Follow the existing pattern:
   ```python
   class NewModule:
       """Description of module"""
       
       @staticmethod
       def method_name(params):
           """Method description"""
           # Implementation
   ```

4. Add menu option in `print_menu()`
5. Add handler in `main()` function
6. Update README.md with new feature

## Legal and Ethical Requirements

All contributions must:
- Be legal and ethical
- Include appropriate warnings and disclaimers
- Not facilitate unauthorized access
- Follow responsible disclosure principles
- Respect privacy and security

## Documentation

- Update README.md for new features
- Add usage examples
- Document any new dependencies
- Update help text and docstrings

## What We're Looking For

Priority contributions:
- Bug fixes
- Performance improvements
- Additional scanning modules
- Better error handling
- Cross-platform compatibility
- Documentation improvements
- Unit tests

## Questions?

- Open an issue for questions
- Tag with `question` label
- Be specific about your question

## Recognition

Contributors will be:
- Listed in README.md acknowledgments
- Credited in release notes
- Mentioned in commit history

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make DIRO better! 🚀
