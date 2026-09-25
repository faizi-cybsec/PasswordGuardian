# Password Guardian Pro
### AI Password Security Analyzer — v2.0

Programming Fundamentals Course Project
Department: BS Cyber Security
Developer: Faizan Ahmed
University: Superior University

Password Guardian Pro is the polished, professional version of the original
Password Guardian tool. Every core feature has been preserved and upgraded —
the password strength analysis, the hand-written SHA-1 implementation, the
Have I Been Pwned breach check, and the password generator — while the
console UI has been made consistent from screen to screen so the whole
program feels like a single piece of security software instead of a set of
separate demos.

## Features

- **Password Strength Analyzer** — length, character classes, unique
  character count and diversity, dictionary words, common passwords,
  keyboard patterns, repeated characters/words, sequential letters/numbers,
  ascending/descending patterns, years, names, emails, phone-number-like
  digit runs, date-of-birth-like digit runs, spaces, unicode characters,
  consecutive repeated symbols, predictable leet-speak substitutions, and
  weak prefixes/suffixes.
- **Entropy Engine** — entropy in bits, complexity label, search space, and
  a plain-English explanation of what entropy means.
- **Crack Time Estimation** — online, offline, GPU, dictionary, hybrid and
  brute-force attack estimates, formatted from seconds up to millions of
  years.
- **Weighted Security Score (0–100)** with letter grades A+ through F and a
  plain-English strength label (Very Weak → Very Strong).
- **Threat Level** — SAFE / LOW / MEDIUM / HIGH / CRITICAL, color-coded.
- **AI Explanation Engine** — explains *why* a password scored the way it
  did (low entropy, dictionary words, repeated characters, predictable
  sequences, weak suffixes, short length, low character diversity, etc.)
  instead of just labeling it.
- **AI Recommendations** — specific, actionable improvement tips.
- **Password Security Dashboard** — a single professional report combining
  every module above, with a consistent set of animated/visual ASCII
  progress bars.
- **Password Generator** — Easy / Medium / Strong / Military / Custom
  levels, selectable lengths (8/12/16/20/24/32), toggleable character
  types, an "avoid ambiguous characters" option, and multi-password
  generation. The primary generated password is shown inside a bordered
  box and is immediately run through the full dashboard.
- **Attack Simulator (educational only)** — a visual, non-functional
  simulation of dictionary, hybrid, rainbow-table, GPU brute-force and
  plain brute-force attacks, paired with real crack-time estimates and a
  closing "Overall Password Resistance" summary. It never performs an
  actual attack.
- **Security Facts** — 100+ built-in cybersecurity facts. One is shown as
  a numbered "Cyber Tip" on every launch and on the Security Tips page,
  and a plain "Did You Know?" fact is shown after every analysis.
- **Have I Been Pwned Breach Check** — the k-Anonymity approach (only the
  first 5 hash characters are ever sent), with a privacy explanation,
  connection status, occurrence count and risk explanation.
- **Professional startup sequence** — a project info panel followed by an
  animated module-loading sequence and the tip of the session.

## Menu

```
[1] Analyze Password
[2] Generate Password
[3] Breach Database
[4] Attack Simulator (Educational)
[5] Security Tips
[6] About
[0] Exit
```

## Project Structure

```
PasswordGuardianPro/
├── main.cpp                   Menu, banner, startup screen, program entry
├── Utils.h / Utils.cpp        Colors, display helpers, shared animated
│                               loading bar, footer, box printer, facts
├── PasswordAnalyzer.h/.cpp    Pattern analysis, scoring, AI explanations
├── Entropy.h / Entropy.cpp    Entropy math and crack-time estimation
├── HIBP.h / HIBP.cpp          SHA-1 implementation + breach checking
├── PasswordGenerator.h/.cpp   Password generator
├── AttackSimulator.h/.cpp     Educational (non-real) attack simulation
├── PasswordGuardianPro.sln
└── PasswordGuardianPro.vcxproj / .vcxproj.filters
```

## Requirements

- Windows 10+ recommended (for native ANSI color support)
- Visual Studio 2022 with the "Desktop development with C++" workload
- MSVC compiler, C++17 language standard
- `curl` available on the PATH (used only for the Have I Been Pwned check;
  every other feature works fully offline)

## Building in Visual Studio 2022

1. Open `PasswordGuardianPro.sln`.
2. Confirm **C++ Language Standard** is set to `/std:c++17` (already
   configured in the provided `.vcxproj`).
3. Build with **Build → Build Solution** (`Ctrl+Shift+B`).
4. Run with **F5** (Debug) or **Ctrl+F5** (Run without debugging).

## Building from the command line

**g++ (MinGW or any POSIX system):**
```bash
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordAnalyzer.cpp \
    Entropy.cpp HIBP.cpp PasswordGenerator.cpp AttackSimulator.cpp \
    -o PasswordGuardianPro
```

**MSVC (Developer Command Prompt):**
```bat
cl /std:c++17 /EHsc main.cpp Utils.cpp PasswordAnalyzer.cpp Entropy.cpp ^
   HIBP.cpp PasswordGenerator.cpp AttackSimulator.cpp ^
   /Fe:PasswordGuardianPro.exe
```

## Notes

- The Have I Been Pwned check requires an internet connection and `curl`.
  Every other menu option works completely offline.
- The Attack Simulator never performs a real attack against any system —
  it only visualizes the concept and shows realistic time estimates
  calculated from entropy.
- Password Comparison, a Policy Checker, History, and a Report exporter
  existed in an earlier version of this project. They were removed in
  v2.0 to keep the menu focused on the seven features above.
