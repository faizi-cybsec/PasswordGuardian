/*
    ============================================================
    UTILS.H
    ============================================================
    Shared helper functions used across the whole program:
      - Console colors (ANSI escape codes)
      - Simple display helpers (titles, rows, checklists, bars)
      - A single reusable animated loading bar
      - A bordered box printer
      - A shared professional footer
      - A library of random cybersecurity facts

    Keeping every screen's borders, bars, headings and footer
    routed through these same functions is what makes the whole
    program look consistent from screen to screen.
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// ---- Console colors (ANSI escape codes) ----
// These are declared here with "extern" and defined once inside
// Utils.cpp. That way every file that includes Utils.h can use
// COLOR_RED, COLOR_GREEN, etc. without redefining them.
extern const std::string COLOR_RESET;
extern const std::string COLOR_GREEN;
extern const std::string COLOR_YELLOW;
extern const std::string COLOR_RED;
extern const std::string COLOR_BLUE;
extern const std::string COLOR_CYAN;
extern const std::string COLOR_WHITE;
extern const std::string COLOR_MAGENTA;

// A full-width separator line, reused everywhere for a consistent look
extern const std::string LINE;

// ---- Basic display helpers ----
void printLine();
void printThinLine();
void printTitle(const std::string &title);
void printRow(const std::string &label, const std::string &value);
void printSection(const std::string &label);
void printCheckRow(bool passed, const std::string &label);
void pauseScreen();

// Prints the same "Password Guardian Pro v2.0 / Developed by
// Faizan Ahmad / Superior University" block at the bottom of
// every screen, framed by separator lines.
void printFooter();

// Prints one or more lines of text inside a simple ASCII box,
// e.g. used to display a freshly generated password.
void printBox(const std::vector<std::string> &lines);

// Turns a true/false result into "YES" / "NO" text
std::string yesNo(bool value);

// Builds a labeled progress bar showing a fixed value out of a
// maximum, e.g.  Entropy   [===============>       ] 68%
// Used for "result" bars (entropy, complexity, security score)
// that show a single final value rather than an animation.
std::string buildProgressBar(const std::string &label, int value, int maxValue);

// The ONE reusable animated loading bar used everywhere the
// program needs to look like it is working: the startup module
// loader, the HIBP connection check, and the attack simulator.
// It always fills gradually from 0% to 100% - it never jumps
// straight to the end - and finishes with a green [OK] tag.
void showLoadingStep(const std::string &label);

// Picks a color based on a 0-100 style score
// (used for security score, entropy score, complexity score, etc.)
std::string getScoreColor(int score);

// Returns one random cybersecurity fact from an internal list of
// at least 100 facts. Used to show a "did you know?" tip after
// every password analysis.
std::string getRandomSecurityFact();

// Picks one random fact from the same internal list and prints
// it as a numbered "Cyber Tip #N", used on the startup screen
// and the Security Tips page.
void printRandomCyberTip();

// Returns the current date as a text string, e.g. "2026-07-24"
std::string getCurrentDateString();

// Returns the current time as a text string, e.g. "14:35:02"
std::string getCurrentTimeString();
