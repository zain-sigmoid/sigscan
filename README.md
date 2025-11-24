<h1 align="center">🔍 Sigscan - Command Line Interface</h1>

<p align="center">
  <a href="https://github.com/zain-sigmoid/sigscan-cli/releases">
    <img src="https://img.shields.io/github/v/release/zain-sigmoid/sigscan-cli?color=blue" alt="version"/>
  </a>
  <a href="https://github.com/zain-sigmoid/sigscan-cli/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Sigmoid%20License-red.svg" alt="license"/>
  </a>
  <img src="https://img.shields.io/badge/python->=3.9-yellow" alt="python"/>
  <img src="https://img.shields.io/badge/platform-MacOS%20%7C%20linux-cyan" alt="platform"/>
</p>

Sigscan is a unified static analysis and compliance framework that integrates multiple scanners into one command-line tool.
It performs end-to-end code intelligence covering security, privacy, performance, and maintainability to help developers ship robust and compliant code faster

## ✨ Features
- 🔐 Security Analysis: Secrets, vulnerabilities, injection attacks
- 🛡️ Privacy Compliance: PII/PHI detection, GDPR/HIPAA compliance
- 📊 Code Quality: Readability, maintainability, performance
- 🧪 Testing & Observability: Test coverage, logging analysis
- 🧰 Maintainability: Cyclomatic Complexity, Maintainability Index
- ⚙️ Performance: Inefficient code patterns, resource usage

## Additional Features & Changes

### Gitleaks Integration
- The CLI automatically ensures gitleaks is available
- Downloads & sets up Gitleaks into /tmp if not found in PATH(Only for Linux, for MacOS install using HomeBrew)
- Falls back to system-installed gitleaks when available
- Uses pure Python (urllib + tarfile) — no wget/tar dependency
- Security analyzers call ensure_gitleaks() before scanning

### Input Modes
- **Project Directory:** Scan a local folder (recommended) as well as through provided Path
- Skips unwanted dirs (__MACOSX, hidden files)
- Guards against path traversal
- Auto-detects likely project root (folder with most .py files)
- **Single File:** Analyze a single .py file when provided instead of Path

## 📦 Installation
### 🧰 Prerequisities(MacOS)
- **Install Xcode command line tools**
    ```bash
    xcode-select --install
    ```
- **Install required dependencies via Homebrew**
    ```bash
    brew install pkg-config icu4c
    ```

- **Export ICU path for pkg-config (needed for build)**
    ```bash
    echo 'export PKG_CONFIG_PATH="$(brew --prefix icu4c)/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.zshrc
    ```
    ```bash
    source ~/.zshrc
    ```
- **Install Gitleaks on MacOS**
    ```bash
    brew install gitleaks
    ```

### 🧰 Prerequisities(Linux)
- **Dependencies**
    ```bash
    sudo apt-get update && sudo apt-get install -y pkg-config libicu-dev build-essential
    ```

*Quit VS Code and restart for updating terminal environment*

### Optional quick test
```bash
pkg-config --modversion icu-i18n
```
*It should print version (e.g., 74.2), you’re good to go 🚀.*


## 🏗️ Install From Source
```bash
pip install git+https://github.com/zain-sigmoid/sigscan-cli.git
```

## 🚀 Quick Start

**Scan current directory**
```bash
sigscan . -o output_file.json
```

**Scan any other directory**
```bash
sigscan path -o output_file.json
```

**Scan a single file**
```bash
sigscan file_path/file.py -o output.json
```

## 📘 CLI Usage
```bash
usage: sigscan [-h] [-a ANALYZER] [--all-analyzers] [--parallel] [--include-low-confidence] [--timeout TIMEOUT]
               [--max-findings MAX_FINDINGS] [-o FILE] [--compact] [--no-progress] [-v] [--quiet] [--logs] [--version]
               [--list-analyzers]
               [path]

Run signature scanning/analysis over a path with a configurable setup.

positional arguments:
  path                  File or directory to analyze. By default scan the current folder from terminal

options:
  -h, --help            show this help message and exit
  -a ANALYZER, --analyzer ANALYZER
                        Enable only these analyzers (repeatable, by name).
  --all-analyzers       Enable all available analyzers.
  --parallel            Does Parallel Processing for faster execution
  --include-low-confidence
                        Includes findings with Low Confidence
  --timeout TIMEOUT     Waiting time in sec, default 900
  --max-findings MAX_FINDINGS
                        Finding threshold for individual analyzer, default 1000
  -o FILE, --out FILE   Write JSON result to FILE (no stdout on success).
  --compact             Minified JSON.
  --no-progress         Hide Analyzer progress information
  -v, --verbose         Use for checking error i.e. traceback
  --quiet               Only show warnings and errors logs, hides info logs.
  --logs                Print the previous saved logs from log file.
  --version             Show the sigscan CLI version and exit.
  --list-analyzers      List available analyzers and exit.
```

## 📤 Output
- JSON file saved in the current directory<br>
This file can be uploaded on the tool to view the result at <a href="https://code-quality.streamlit.app/" target="_blank">Sigscan Tool</a>

## 🧩 Troubleshooting
**“gitleaks not found”**<br>
The CLI will auto-download for Linux; ensure your environment allows network access and /tmp write permissions.<br>
On MacOS you can download via brew
```bash
brew install gitleaks
```


## 🛠️ Local Development
```bash
git clone https://github.com/zain-sigmoid/sigscan-cli
cd sigscan-cli
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
# run from repo root:
sigscan --help
```

## 📄 License
This project is proprietary and intended for internal use only by authorized Sigmoid Analytics employees and contractors.
