# 🛡️ Password Guardian
### *AI-Powered Password Security Analyzer & Threat Assessment Suite*

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-Build_System-064F8C?logo=cmake&logoColor=white)](https://cmake.org/)
[![License](https://img.shields.io/github/license/faizi-cybsec/PasswordGuardian?color=green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/faizi-cybsec/PasswordGuardian?style=flat)](https://github.com/faizi-cybsec/PasswordGuardian/stargazers)

**Password Guardian** is a comprehensive, production-grade console security suite engineered to evaluate, score, and simulate threats against authentication credentials. Developed as an advanced academic milestone, it wraps multi-layered cryptographic checks, Shannon Entropy evaluations, and k-Anonymity breach verification engines inside an intuitive, ANSI-colored dashboard.

---

## 🏛️ Academic Context
- **Course:** Programming Fundamentals (Project Milestone)
- **Department:** BS Cyber Security
- **Developer:** [Faizan Ahmed](https://github.com/faizi-cybsec)
- **Institution:** Superior University

---

## 🎯 Key Capabilities & Core Engines

### 🔍 1. Password Strength Analyzer
Evaluates input credentials against multi-tier structural criteria using localized analysis routines:
- **Pattern Matching:** Detects predictable keyboard paths, sequential character runs, leet-speak mutations, dates of birth, common prefixes, and structural suffixes.
- **Diversity Profiling:** Scans for character space breadth, uniqueness ratios, and literal dictionary collisions.

### 🧠 2. Shannon Entropy & Crack-Time Engine
- **Mathematical Scoring:** Computes true mathematical entropy bits to map actual algorithmic search spaces.
- **Brute-Force Benchmarks:** Projects real-world decryption estimates across distinct environments (Online, Offline, High-Performance GPU Arrays, and Hybrid Dictionary attacks).

### 🤖 3. AI Explanation & Recommendation Engine
- **Contextual Metrics:** Goes beyond metric output by explaining *why* structural patterns introduce systemic vulnerabilities.
- **Actionable Advice:** Generates precise, dynamic suggestions to patch entropy weaknesses.

### 🔑 4. Dynamic Generation & Simulation
- **Military-Grade Generator:** Deploys structured policies (Easy, Medium, Strong, Military, Custom) with unique safety rules like "exclude ambiguous glyphs".
- **Educational Attack Simulator:** Visualizes dictionary, rainbow table, and brute-force methodologies paired with an interactive cryptographic tips matrix featuring over 100+ cybersecurity insights.

### 🌐 5. Zero-Knowledge HIBP Leak Checker
- **k-Anonymity Integration:** Leverages raw `SHA-1` hashing routines locally. It transmits only the **first 5 characters** of the hex-hash to the *Have I Been Pwned API* via secure curl bindings, preserving zero-knowledge privacy constraints.

---

## 💻 Interactive Console Shell Interface

The terminal shell organizes modules cleanly through a structured control deck:

```text
=====================================================
               PASSWORD GUARDIAN PRO v2.0            
=====================================================
   [1] Analyze Password
   [2] Generate Password
   [3] Breach Database (HIBP Check)
   [4] Attack Simulator (Educational)
   [5] Security Tips Dashboard
   [6] About the Software
   [0] Exit Application
=====================================================
```

---

## 📂 Project Architecture

```text
PasswordGuardian/
├── include/                 # Logic declarations and header files
│   ├── AttackSimulator.h    # Educational threat simulation schemas
│   ├── Entropy.h            # Bit-entropy mathematics & crack-time matrices
│   ├── HIBP.h               # Local SHA-1 hashing & API communication structure
│   ├── PasswordAnalyzer.h   # Multi-pattern parsing & scoring logic
│   ├── PasswordGenerator.h  # Custom profile generation array
│   └── Utils.h              # ANSI layout engines, loaders, & tip arrays
├── src/                     # Core system code implementations
│   ├── main.cpp             # Terminal control deck and engine orchestrator
│   ├── AttackSimulator.cpp
│   ├── Entropy.cpp
│   ├── HIBP.cpp
│   ├── PasswordAnalyzer.cpp
│   ├── PasswordGenerator.cpp
│   └── Utils.cpp
├── .gitignore               # Strict build/cache tracking ignore layer
├── CMakeLists.txt           # Unified cross-platform build automation script
└── LICENSE                  # MIT Open-Source Authorization File
```

---

## ⚙️ Compilation Environment Requirements

| Target Requirement | Description |
| :--- | :--- |
| **Operating System** | Windows 10+ (Recommended for native Virtual Terminal ANSI Colors), Linux, or macOS |
| **Compiler Toolchain** | MSVC v143+, GCC 9+, or Clang 10+ |
| **Language Standard** | `C++17` (`/std:c++17` or `-std=c++17`) |
| **External Dependency** | `curl` must be present on your system's global environment PATH variable |

---

## 🛠️ Build and Installation Instruction Matrix

### Method 1: Cross-Platform Build Automation (Recommended)
This approach leverages the embedded CMake build script. It supports native environments globally across Windows, Mac, or Linux systems:

```bash
# 1. Create a clean out-of-source binary generation folder
mkdir build && cd build

# 2. Configure build files via CMake
cmake ..

# 3. Execute the compiler toolchain to build the binary
cmake --build .

# 4. Fire up the application module
./PasswordGuardianPro
```

### Method 2: Native Visual Studio 2022 Integration
1. Launch **Visual Studio 2022**.
2. Select **Open a local folder** on the splash screen and select your cloned repository directory.
3. Visual Studio will natively process the `CMakeLists.txt` profile and configure your target workspace cache automatically.
4. Press **Ctrl + Shift + B** to execute a clean project build, and press **F5** to start execution.

### Method 3: Manual Command Line Processing
If you prefer raw execution workflows without a build automation framework:

```bash
# Using GCC / MinGW-w64 G++ Toolchain
g++ -std=c++17 -Wall -Wextra src/*.cpp -Iinclude -o PasswordGuardianPro

# Using MSVC Developer Command Prompt Shell
cl /std:c++17 /EHsc src/*.cpp /Iinclude /Fe:PasswordGuardianPro.exe
```

---

## 📝 Important Implementation Details
- **Network Bound Constraints:** The *Have I Been Pwned* breach index requires an active internet connection to query curl boundaries. If connection parameters are unavailable, all other analysis engines continue executing completely offline.
- **Threat Simulation Boundaries:** The interactive attack simulator is strictly an educational tool designed for proof-of-concept visual modeling. It does not interface with or run active attacks against remote verification layers.
- **Privacy Controls:** Session history metrics are maintained entirely in volatility-bound runtime memory. Passwords are explicitly masked and never cached to disk files, safeguarding your session data.
