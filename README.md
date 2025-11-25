# 🔍 Sigscan - Code Review Tool
Unified analysis platform combining multiple security, quality, and compliance checkers for Streamlit-based workflows.

## ✨ Core Capabilities
- 🔐 Security analysis for secrets, vulnerabilities, and injection risks.
- 🛡️ Privacy compliance checks for PII/PHI and regulatory alignment.
- 📊 Code quality metrics covering readability, maintainability, and complexity.
- 🧪 Testing and observability insights for coverage and logging gaps.
- ⚙️ Performance profiling to highlight inefficient or resource-heavy code paths.

## 🔧 Key Enhancements
- **Gitleaks integration:** The `ensure_gitleaks()` helper bootstraps Gitleaks in `/tmp` when it is not already present and falls back to the system binary when available.  
  - Linux environments are handled automatically.  
  - macOS users should install Gitleaks once with `brew install gitleaks`; the app will detect the binary afterwards.
- **ZIP project uploads:** Upload entire projects as `.zip` archives. The extractor sanitizes paths, skips unwanted folders (such as `__MACOSX`), and auto-detects the most relevant project root.
- **Single-file uploads:** Analyze an individual `.py` file directly without repackaging the project.

## 🚀 Getting Started
```bash
git clone https://github.com/zain-sigmoid/gstool.git
cd gstool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Populate required secrets before running
```

### Launch the UI
```bash
streamlit run main_consolidated.py
```

## 🧪 Using the Analyzer
1. Upload a project ZIP or a single Python file.
2. Click **Run Analysis** to trigger the analyzer suite (Maintainability, Injection, Performance, Privacy, and more).
3. Review the dashboard for:  
   - Summary metrics (execution time, files analyzed, error counts).  
   - Detailed findings with severity, explanations, and remediation guidance.

## 🖥️ CLI Workflow Option
Prefer running scans locally? Use the CLI and import the results into the UI.

```bash
sigscan path -o out.json
sigscan path -a <analyzer_name> -o out.json
```

After generating `out.json`, upload it through the UI to visualize the findings. Installation notes for the CLI are available in the [sigscan-cli repository](https://github.com/zain-sigmoid/sigscan-cli).

## 📄 License
This project is proprietary and intended for internal use only by authorized Sigmoid Analytics employees and contractors.
