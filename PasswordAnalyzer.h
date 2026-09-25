/*
    ============================================================
    PASSWORDANALYZER.H
    ============================================================
    Password Guardian Pro — Password Intelligence Module

    Defines the structural data model for pattern checks, scoring,
    and dashboard visualization prototypes.
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// ----------------------------------------------------------------
// PasswordAnalysis Data Model
// ----------------------------------------------------------------
// Captures character distributions, pattern flags, and vulnerability
// signals detected during password evaluation.
struct PasswordAnalysis
{
    std::string password;

    // Character Counts & Diversity Metrics
    int length = 0;
    int upperCount = 0;
    int lowerCount = 0;
    int digitCount = 0;
    int specialCount = 0;
    int uniqueCount = 0;
    double diversityPercent = 0.0;

    // Vulnerability & Pattern Signal Flags
    bool isDictionaryWord = false;
    bool isCommonPassword = false;
    bool hasKeyboardPattern = false;
    bool hasRepeatedChars = false;
    bool hasRepeatedWords = false;
    bool hasSequentialLetters = false;
    bool hasSequentialNumbers = false;
    bool hasAscendingPattern = false;
    bool hasDescendingPattern = false;
    bool containsYear = false;
    bool containsName = false;
    bool containsEmail = false;
    bool containsPhonePattern = false;
    bool containsDobPattern = false;
    bool containsSpaces = false;
    bool containsUnicode = false;
    bool hasConsecutiveRepeatedSymbols = false;
    bool hasPredictableSubstitution = false;
    bool hasWeakSuffix = false;
    bool hasWeakPrefix = false;
};

// Character Class Detection Helpers
bool hasUppercase(const std::string& password);
bool hasLowercase(const std::string& password);
bool hasDigit(const std::string& password);
bool hasSpecialChar(const std::string& password);

// Core Analysis Pipeline
PasswordAnalysis analyzePassword(const std::string& password);

// Scoring, Grading & Threat Evaluation
int calculateSecurityScore(const PasswordAnalysis& analysis, double entropyBits);
std::string getSecurityGrade(int score);
std::string getStrengthLabel(int score);
std::string getThreatLevel(int score);
std::string getThreatLevelColor(const std::string& threatLevel);

// Intelligence Engines
std::vector<std::string> generateExplanations(const PasswordAnalysis& analysis, double entropyBits);
std::vector<std::string> generateRecommendations(const PasswordAnalysis& analysis);

// High-Impact Visual Dashboard
void printPasswordDashboard(const PasswordAnalysis& analysis);