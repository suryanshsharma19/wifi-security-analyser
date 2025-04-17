# Contributing to WiFi Security Analyzer

Thank you for your interest in contributing to WiFi Security Analyzer! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## How to Contribute

### 1. Reporting Issues

- Check if the issue has already been reported
- Use a clear and descriptive title
- Include steps to reproduce the issue
- Provide expected and actual behavior
- Include system information and version numbers

### 2. Feature Requests

- Use a clear and descriptive title
- Explain why this feature would be useful
- Provide examples of how it would work
- Consider suggesting implementation approaches

### 3. Pull Requests

1. Fork the repository
2. Create a new branch for your feature
3. Make your changes
4. Test your changes thoroughly
5. Submit a pull request

### 4. Development Setup

1. Clone the repository:
```bash
# git clone <repository_url>
# cd wifi_security_analyser
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

# Optional: Run any available tests if applicable
# (Currently, specific test commands depend on the testing framework used)

### 5. Code Style

- Follow PEP 8 style guide
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small
- Write docstrings for all public functions

### 6. Testing

- Write unit tests for new features
- Ensure all tests pass before submitting
- Update tests when modifying existing features
- Test on multiple platforms if possible

### 7. Documentation

- Update README.md for significant changes
- Add docstrings to new functions
- Update inline comments when modifying code
- Keep the wiki up to date

## Project Structure

```
wifi_security_analyser/
├── GUI_Module.py          # Main GUI application
├── wifi_analyzer.py       # Core analysis logic (if separated)
├── modules/               # Directory for helper modules
├── config.json            # Configuration file
├── requirements.txt       # Dependencies
├── README.md              # Project documentation
├── LICENSE                # License file
├── CONTRIBUTING.md        # Contributing guide
├── WINDOWS_SETUP.md       # Windows setup specifics
└── logs/                  # Directory for log files (if used)
```

## Development Workflow

1. Create an issue describing your planned changes
2. Fork the repository
3. Create a feature branch
4. Make your changes
5. Run tests
6. Submit a pull request
7. Address any feedback
8. Wait for review and merge

## Getting Help

- Check the documentation
- Join our Discord community
- Open an issue
- Contact the maintainers

## Recognition

Contributors will be recognized in:
- Project README
- Release notes
- Documentation

Thank you for contributing to WiFi Security Analyzer! 