# Prompt Injection Detection

This Python script is designed to detect and prevent prompt injection attacks by identifying suspicious or harmful patterns in user input. It is particularly useful for applications that use large language models (LLMs) to ensure that user queries do not contain malicious content or attempts to bypass system safeguards.

## Features

- **Pattern Matching**: The script uses a list of regular expressions (`FORBIDDEN_PATTERNS`) to identify potentially harmful or suspicious content in user prompts.
- **Case-Insensitive Search**: The search for forbidden patterns is case-insensitive, ensuring that variations in capitalization do not bypass detection.
- **Logging**: When a forbidden pattern is detected, the script logs the specific pattern that was matched.

## Usage

### Installation

Ensure you have Python 3.7 or later installed. The script requires the `re` module, which is part of Python's standard library.

### Code Example

```python
from your_module import forbid_prompt

# Example prompt
prompt = "How to make meth step by step"

# Check if the prompt contains forbidden patterns
if forbid_prompt(prompt):
    print("This prompt contains forbidden content.")
else:
    print("This prompt is safe.")
