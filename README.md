<div align="center">

# 🔐 Password Guardian

### Password Security Analyzer & Live Breach Checker

<p>
  <strong>Analyze • Generate • Verify • Protect</strong>
</p>
<img width="929" height="961" alt="Screenshot 2026-09-25 234637" src="https://github.com/user-attachments/assets/0d534ad5-edce-4db1-b589-519294661f4d" />

<p>
  A terminal-based cybersecurity tool for analyzing password strength,
  estimating entropy and crack resistance, generating secure passwords,
  and checking passwords against known breach data.
</p>

<p>
  <a href="https://github.com/faizi-cybsec/PasswordGuardian">
    <img src="https://img.shields.io/badge/Language-C%2B%2B17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++17">
  </a>
  <a href="https://cmake.org/">
    <img src="https://img.shields.io/badge/Build-CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white" alt="CMake">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/faizi-cybsec/PasswordGuardian?style=for-the-badge" alt="MIT License">
  </a>
  <a href="https://github.com/faizi-cybsec/PasswordGuardian/stargazers">
    <img src="https://img.shields.io/github/stars/faizi-cybsec/PasswordGuardian?style=for-the-badge" alt="GitHub Stars">
  </a>
</p>

<p>
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-security">Security</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-contributing">Contributing</a>
</p>

</div>

---

## 🛡️ Overview

**Password Guardian** is a C++ based password security toolkit designed to help users understand and improve password security through practical analysis.

Instead of simply telling you whether a password is "strong" or "weak", Password Guardian examines multiple security characteristics such as:

* Password length
* Character diversity
* Entropy
* Estimated crack resistance
* Common password characteristics
* Exposure in known compromised-password datasets

It also provides a password generator, security recommendations, and an educational attack simulation designed to demonstrate why weak passwords are dangerous.

> **Password Guardian is an educational security tool. It is designed to help users understand password security and make better password choices.**

---

## ✨ Features

### 🔍 Password Strength Analysis

Evaluate passwords using multiple characteristics instead of relying only on length.

Password Guardian can analyze:

* Length
* Uppercase characters
* Lowercase characters
* Numbers
* Special characters
* Character-space diversity
* Overall password strength

---

### 📊 Shannon Entropy Analysis

Password Guardian calculates **Shannon entropy** to provide an additional statistical perspective on password complexity.

Entropy can help demonstrate how much uncertainty exists within a password and why larger, more diverse character spaces generally provide stronger resistance against guessing.

---

### ⏱️ Crack-Time Estimation

Password Guardian provides an estimated crack-time calculation based on password characteristics and configurable assumptions.

The purpose is educational:

> A password that appears complex to a human is not necessarily resistant to automated guessing.

Crack-time estimates should therefore be treated as **approximations**, not guarantees.

---

### 🎲 Secure Password Generator

Generate passwords using different security profiles.

The generator is designed to help users create passwords that are:

* Longer
* More random
* More difficult to guess
* Suitable for different security requirements

Instead of creating passwords such as:

```text
Password123
Welcome123
Faizan@123
```

Password Guardian can generate significantly stronger alternatives.

---

### 🌐 Have I Been Pwned Integration

Password Guardian can check whether a password appears in the **Have I Been Pwned Pwned Passwords** dataset.

The implementation is designed around the API's privacy-preserving **k-anonymity** approach.

The password is hashed locally, and only a partial hash prefix is sent to the service. The returned hash suffixes are then compared locally.

This means the complete password is not sent to the Pwned Passwords API.

Learn more:

* [Have I Been Pwned – Pwned Passwords](https://haveibeenpwned.com/Passwords)
* [Have I Been Pwned API Documentation](https://haveibeenpwned.com/API/v3)

---

### 🧪 Educational Attack Simulation

Password Guardian includes an educational attack-simulation component to demonstrate how password guessing can work against weak passwords.

The purpose is **security education**, not unauthorized access.

It helps users understand concepts such as:

* Guessing attacks
* Password complexity
* Search spaces
* Weak-password risk
* Why longer passwords matter

> ⚠️ Use security testing and attack simulation only in environments you own or have explicit permission to test.

---

### 🛡️ Security Recommendations

Password Guardian provides practical recommendations based on password-analysis results.

Examples include:

* Increase password length
* Use greater character diversity
* Avoid predictable patterns
* Avoid reused passwords
* Avoid passwords found in breach datasets
* Prefer randomly generated passwords
* Use unique passwords for different services

---

### 💻 Terminal Interface

Password Guardian is designed around a terminal-based interface with ANSI styling.

The interface focuses on:

* Clear security results
* Readable output
* Simple navigation
* Security-focused terminology
* Lightweight execution

---

## 🧠 Why Password Security Matters

Passwords remain one of the most common authentication mechanisms, but weak or reused passwords can significantly increase the impact of credential attacks.

A password can appear strong because it contains:

```text
Uppercase + lowercase + numbers + symbols
```

while still being predictable.

For example:

```text
Password@123
Admin@2026
Welcome#123
```

Password Guardian approaches password evaluation from several angles rather than relying on a single "strong/weak" rule.

---

## 🔐 Security Model

Password Guardian combines several concepts when evaluating passwords:

```text
                  ┌──────────────────────┐
                  │      PASSWORD        │
                  └──────────┬───────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌───────────┐  ┌────────────┐  ┌─────────────┐
        │ Strength  │  │  Entropy   │  │ Breach      │
        │ Analysis  │  │ Analysis   │  │ Check       │
        └─────┬─────┘  └─────┬──────┘  └──────┬──────┘
              │              │                │
              └──────────────┼────────────────┘
                             ▼
                   ┌──────────────────┐
                   │ Security Result  │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │ Recommendations  │
                   └──────────────────┘
```

The result is intended to give users a broader understanding of password security rather than relying on one metric.

---

# ⚙️ Technology Stack

| Technology               | Purpose                                             |
| ------------------------ | --------------------------------------------------- |
| **C++17**                | Core application                                    |
| **CMake**                | Build configuration                                 |
| **SHA-1**                | Password hash generation for Pwned Passwords lookup |
| **HTTP/REST API**        | Breach-data integration                             |
| **ANSI Escape Codes**    | Terminal styling                                    |
| **Standard C++ Library** | Core utilities and data processing                  |

---

# 📁 Project Structure

```text
PasswordGuardian/
│
├── include/
│   ├── AttackSimulator.h
|   ├── Entropy.h
|   ├── HIBP.h
|   ├── PasswordAnalyzer.h
|   ├── PasswordGenerator.h
│   └── Utils.h
│
├── src/
│   ├── AttackSimulator.cpp
|   ├── Entropy.cpp
|   ├── HIBP.cpp
|   ├── PasswordAnalyzer.cpp
|   ├── PasswordGenerator.cpp
|   ├── Utils.cpp
│   └── main.cpp
│
├── CMakeLists.txt
├── README.md
└── LICENSE
```

The project separates headers and implementation files to keep the codebase organized and maintainable.

---

# 🚀 Installation

## Prerequisites

Before building Password Guardian, make sure you have:

* A C++17-compatible compiler
* CMake
* Git
* Internet access for the Pwned Passwords lookup feature

### Linux

On Debian/Ubuntu-based systems:

```bash
sudo apt update
sudo apt install g++ cmake git
```

### Windows

Recommended options:

* Visual Studio with C++ development tools
* MinGW
* CMake
* Git

Verify your installation:

```bash
g++ --version
cmake --version
git --version
```

---

# 📥 Clone the Repository

```bash
git clone https://github.com/faizi-cybsec/PasswordGuardian.git
cd PasswordGuardian
```

---

# 🔨 Build

Create a build directory:

```bash
mkdir build
cd build
```

Configure the project:

```bash
cmake ..
```

Build:

```bash
cmake --build .
```

Depending on your platform and CMake generator, the resulting executable may be located in a different directory.

---

# ▶️ Run

After building, run the generated Password Guardian executable.

### Linux/macOS

```bash
./PasswordGuardian
```

### Windows

The executable may be generated inside the appropriate CMake build directory, for example:

```powershell
.\Debug\PasswordGuardian.exe
```

or:

```powershell
.\PasswordGuardian.exe
```

The exact path depends on the compiler and CMake generator being used.

---

# 🖥️ Usage

After launching Password Guardian, use the terminal interface to access the available security functions.

A typical workflow looks like:

```text
┌─────────────────────────────────────────────┐
│              PASSWORD GUARDIAN              │
├─────────────────────────────────────────────┤
│                                             │
│  [1] Analyze Password                       │
│  [2] Generate Password                      │
│  [3] Check Password Exposure                │
│  [4] Attack Simulation                      │
│  [5] Security Recommendations               │
│  [0] Exit                                   │
│                                             │
└─────────────────────────────────────────────┘
```

> The exact menu and available options may change as the project evolves.

---

# 🔎 Example Analysis

A password analysis can provide information such as:

```text
Password Security Analysis
────────────────────────────────────

Length              : 16
Character Diversity : High
Entropy             : High
Estimated Resistance: Strong
Breach Status       : Not Found

Recommendation:
✓ Use a unique password
✓ Avoid password reuse
✓ Consider using a password manager
```

The exact output depends on the password and the current implementation.

---

# 🌐 Pwned Passwords Privacy

Password Guardian's breach-checking functionality is designed around the **Have I Been Pwned Pwned Passwords range API**.

The process can be summarized as:

```text
             USER PASSWORD
                    │
                    ▼
             Local SHA-1 Hash
                    │
                    ▼
          First 5 Characters
                    │
                    ▼
       Pwned Passwords API
                    │
                    ▼
        Hash Suffixes Returned
                    │
                    ▼
           Local Comparison
                    │
             ┌──────┴──────┐
             ▼             ▼
           FOUND         NOT FOUND
             │             │
             ▼             ▼
       Compromised      No Match
```

The full password is not sent to the service.

According to the HIBP documentation, the range API receives the first five characters of a SHA-1 or NTLM hash and returns matching suffixes and prevalence counts for local comparison.

---

# ⚠️ Important Security Notes

Password Guardian is an **educational security tool**, not a replacement for a professional password manager or enterprise identity-security platform.

### Crack-time estimates

Crack-time calculations are approximations.

Real-world attack speed depends on factors including:

* Hardware
* Hashing algorithm
* Rate limiting
* Password policies
* Attack methodology
* Available wordlists
* Credential stuffing
* Target environment

Therefore:

> **An estimated crack time should never be treated as a guarantee.**

### Password exposure checks

A password not appearing in the Pwned Passwords dataset does **not** prove that the password is secure.

It only means that the password was not found in the dataset queried at the time of checking.

---

# 🧪 Educational Attack Simulation

The attack-simulation functionality exists to demonstrate password-security concepts in a controlled environment.

It should only be used against:

* Your own test data
* Your own systems
* Explicitly authorized environments
* Educational lab environments

Never use Password Guardian to attempt unauthorized access to accounts or systems.

---

# 🎯 Project Goals

Password Guardian was created with several goals:

### 1. Learn Cybersecurity Through Code

Transform cybersecurity concepts into a practical C++ application.

### 2. Understand Password Security

Explore concepts such as:

* Entropy
* Password complexity
* Hashing
* Brute-force concepts
* Credential exposure
* Password generation

### 3. Practice Secure Development

Apply security concepts while building a real software project.

### 4. Build a Practical CLI Security Tool

Create something that can be compiled, executed, tested, and extended rather than remaining purely theoretical.

---

# 🗺️ Roadmap

Future improvements may include:

* [ ] More advanced password-strength heuristics
* [ ] Improved password-generation profiles
* [ ] More detailed analysis reports
* [ ] Configurable attack-simulation parameters
* [ ] Unit testing
* [ ] Automated CI builds
* [ ] Cross-platform testing
* [ ] Improved CLI navigation
* [ ] Exportable security reports
* [ ] Additional password-risk indicators
* [ ] Improved documentation
* [ ] Performance optimizations

> Roadmap items are subject to change as development continues.

---

# 🧪 Testing

Testing is an important part of future development.

Planned testing areas include:

```text
Password Analysis
      │
      ├── Length checks
      ├── Character-set checks
      ├── Entropy calculations
      └── Strength classification

Password Generator
      │
      ├── Length validation
      ├── Character diversity
      └── Randomness checks

Breach Checking
      │
      ├── Hash generation
      ├── API communication
      ├── Prefix handling
      └── Local suffix comparison
```

---

# 🤝 Contributing

Contributions are welcome.

If you want to improve Password Guardian:

### 1. Fork the repository

```bash
git fork
```

Or use GitHub's **Fork** button.

### 2. Clone your fork

```bash
git clone https://github.com/YOUR-USERNAME/PasswordGuardian.git
cd PasswordGuardian
```

### 3. Create a branch

```bash
git checkout -b feature/improve-password-analysis
```

### 4. Make your changes

Implement and test your improvement.

### 5. Commit

```bash
git add .
git commit -m "Improve password analysis"
```

### 6. Push

```bash
git push origin feature/improve-password-analysis
```

### 7. Open a Pull Request

Describe:

* What you changed
* Why you changed it
* How you tested it
* Any limitations or known issues

---

# 🐛 Bug Reports & Feature Requests

Found a problem?

Please open an issue:

👉 [Report an Issue](https://github.com/faizi-cybsec/PasswordGuardian/issues)

When reporting a bug, include:

* Operating system
* Compiler
* CMake version
* Steps to reproduce
* Expected behavior
* Actual behavior
* Relevant error output

Please **never include real passwords, credentials, API keys, or other sensitive information** in issues.

---

# 🔐 Responsible Use

Password Guardian is intended for:

* Cybersecurity education
* Password-security awareness
* Authorized security testing
* Personal security experimentation
* C++ security development
* Security research in controlled environments

The developer does not encourage unauthorized access, credential theft, password attacks against third-party systems, or other illegal activity.

Always obtain permission before performing security testing against systems you do not own.

---

# 📜 License

Password Guardian is released under the **MIT License**.

See the [LICENSE](LICENSE) file for the complete license text.

---

# 🙌 Acknowledgements

Special thanks to the security community and the open-source projects and standards that make security research and education accessible.

### Have I Been Pwned

Password Guardian uses the **Pwned Passwords** service for compromised-password checking.

Learn more:

👉 https://haveibeenpwned.com/Passwords

👉 https://haveibeenpwned.com/API/v3

The Pwned Passwords API provides a privacy-preserving range-search mechanism using k-anonymity.

---

# 👨‍💻 Author

**Faizan Ahmad**

Cybersecurity Student | Security Research & Defensive Security

GitHub:
https://github.com/faizi-cybsec

LinkedIn:
https://www.linkedin.com/in/faizi-cybsec/

---

<div align="center">

### 🔐 Password Guardian

**Analyze • Generate • Verify • Protect**

If you find this project useful, consider giving it a ⭐ on GitHub.

</div>
