# JSIntelliRecon

**JSIntelliRecon** is an advanced JavaScript reconnaissance tool for identifying endpoints, secrets, internal paths, JS library versions, and more — all from JavaScript files found on a target website.

---

## Features

- Extracts external and inline JavaScript
- Detects:
  - API Endpoints
  - Secrets (tokens, keys, passwords)
  - JS Library Versions (e.g., jQuery, React, Angular)
  - Internal Paths (e.g., `/admin/config.php`)
  - IP Addresses
- Supports optional deep crawling for subpages
- Outputs results to a structured JSON file
- Clean, color-coded terminal output

---

## Usage

```
python jsintellirecon.py --url https://example.com --output results.json
```

Enable deep crawl mode:

```
python jsintellirecon.py --url https://example.com --output results.json --deep
```

---

## Output Format
A structured .json file containing:

```
[
  {
    "url": "https://example.com/script.js",
    "endpoints": [...],
    "secrets": [...],
    "versions": [...],
    "internal_paths": [...],
    "ips": [...]
  }
]
```

---

## Installation
Install the required Python libraries:

```
pip install -r requirements.txt
```

---

## Disclaimer

```
JSIntelliRecon is designed for ethical research and testing. Only scan websites you have permission to test.
```
---

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) license.  
See the [LICENSE](LICENSE) file for full details.

Made by Hound0x
