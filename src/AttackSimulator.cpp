/*
    ============================================================
    ATTACKSIMULATOR.CPP
    ============================================================
    This module never performs a real attack.

    It only demonstrates how common password attacks work using
    an animated educational loading bar and displays estimated
    crack times calculated in Entropy.cpp.
    ============================================================
*/

#include "AttackSimulator.h"
#include "Entropy.h"
#include "Utils.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <cctype>
#include <thread>
#include <chrono>

using namespace std;

static const int ATTACK_BOX_WIDTH = 58;

// ============================================================
// GENERAL DISPLAY HELPERS
// ============================================================

// Creates a string containing the requested number of characters.
static string repeatCharacter(char character, int count)
{
    return string(count, character);
}

// Centers text inside a fixed-width space.
static string centerAttackText(const string& text, int width)
{
    if (static_cast<int>(text.length()) >= width)
        return text.substr(0, width);

    int totalSpace = width - static_cast<int>(text.length());
    int leftSpace = totalSpace / 2;
    int rightSpace = totalSpace - leftSpace;

    return string(leftSpace, ' ') + text + string(rightSpace, ' ');
}

// Prints the top, middle, or bottom border of a box.
static void printAttackBorder(int width = ATTACK_BOX_WIDTH)
{
    cout << COLOR_WHITE
        << "+"
        << repeatCharacter('-', width)
        << "+"
        << COLOR_RESET
        << "\n";
}

// Prints an empty row inside a box.
static void printAttackEmptyRow(int width = ATTACK_BOX_WIDTH)
{
    cout << COLOR_WHITE
        << "|"
        << string(width, ' ')
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a centered title inside a box.
static void printAttackTitleRow(
    const string& title,
    const string& color = COLOR_CYAN,
    int width = ATTACK_BOX_WIDTH)
{
    cout << COLOR_WHITE << "|"
        << color
        << centerAttackText(title, width)
        << COLOR_RESET
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a normal text row inside a box.
static void printAttackTextRow(
    const string& text,
    const string& color = COLOR_WHITE,
    int width = ATTACK_BOX_WIDTH)
{
    string visibleText = text;

    if (static_cast<int>(visibleText.length()) > width - 4)
        visibleText = visibleText.substr(0, width - 4);

    int remainingSpace =
        width - 4 - static_cast<int>(visibleText.length());

    cout << COLOR_WHITE << "|  "
        << color
        << visibleText
        << string(remainingSpace, ' ')
        << COLOR_RESET
        << COLOR_WHITE << "  |"
        << COLOR_RESET
        << "\n";
}

// Prints a label and value inside a box.
static void printAttackFieldRow(
    const string& label,
    const string& value,
    const string& valueColor = COLOR_WHITE,
    int width = ATTACK_BOX_WIDTH)
{
    const int labelWidth = 18;

    string displayLabel = label;

    if (static_cast<int>(displayLabel.length()) > labelWidth)
        displayLabel = displayLabel.substr(0, labelWidth);

    int usedLength =
        2 +
        labelWidth +
        3 +
        static_cast<int>(value.length());

    int remainingSpace = width - usedLength;

    if (remainingSpace < 0)
        remainingSpace = 0;

    cout << COLOR_WHITE << "|  "
        << COLOR_CYAN
        << left << setw(labelWidth) << displayLabel
        << COLOR_RESET
        << COLOR_WHITE << " : "
        << valueColor
        << value
        << COLOR_RESET
        << string(remainingSpace, ' ')
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";
}

// Prints long text across multiple box rows.
static void printWrappedAttackText(
    const string& text,
    const string& color = COLOR_WHITE,
    int width = ATTACK_BOX_WIDTH)
{
    const int contentWidth = width - 4;

    size_t position = 0;

    while (position < text.length())
    {
        int remaining =
            static_cast<int>(text.length() - position);

        int take =
            remaining < contentWidth
            ? remaining
            : contentWidth;

        if (take == contentWidth &&
            position + take < text.length())
        {
            size_t lastSpace =
                text.rfind(' ', position + take);

            if (lastSpace != string::npos &&
                lastSpace > position)
            {
                take =
                    static_cast<int>(lastSpace - position);
            }
        }

        string line = text.substr(position, take);

        printAttackTextRow(line, color, width);

        position += take;

        while (position < text.length() &&
            text[position] == ' ')
        {
            position++;
        }
    }
}

// ============================================================
// SECURITY HELPERS
// ============================================================

// Converts a security score into a resistance label.
static string getResistanceLabel(int score)
{
    if (score >= 85)
        return "Very High";

    if (score >= 70)
        return "High";

    if (score >= 50)
        return "Moderate";

    if (score >= 30)
        return "Low";

    return "Very Low";
}

// Determines the risk level for brute-force simulations.
static string getAttackRiskLevel(int score)
{
    if (score >= 85)
        return "LOW";

    if (score >= 70)
        return "LOW-MEDIUM";

    if (score >= 50)
        return "MEDIUM";

    if (score >= 30)
        return "HIGH";

    return "CRITICAL";
}

// Returns the color used for an attack risk level.
static string getAttackRiskColor(const string& riskLevel)
{
    if (riskLevel == "LOW")
        return COLOR_GREEN;

    if (riskLevel == "LOW-MEDIUM")
        return COLOR_CYAN;

    if (riskLevel == "MEDIUM")
        return COLOR_YELLOW;

    return COLOR_RED;
}

// Counts the different character categories used in the password.
static int countCharacterVariety(const string& password)
{
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char character : password)
    {
        unsigned char safeCharacter =
            static_cast<unsigned char>(character);

        if (isupper(safeCharacter))
            hasUppercase = true;
        else if (islower(safeCharacter))
            hasLowercase = true;
        else if (isdigit(safeCharacter))
            hasDigit = true;
        else
            hasSpecial = true;
    }

    int variety = 0;

    if (hasUppercase)
        variety++;

    if (hasLowercase)
        variety++;

    if (hasDigit)
        variety++;

    if (hasSpecial)
        variety++;

    return variety;
}

// Prints a score bar using Windows console block characters.
static void printResistanceBar(
    int score,
    int width = ATTACK_BOX_WIDTH)
{
    const int labelWidth = 20;
    const int barLength = 20;

    int filledBlocks = (score * barLength) / 100;

    if (filledBlocks < 0) filledBlocks = 0;
    if (filledBlocks > barLength) filledBlocks = barLength;

    string scoreColor = getScoreColor(score);

    cout << COLOR_WHITE << "|  "
        << COLOR_CYAN
        << left << setw(labelWidth) << "Resistance Progress"
        << COLOR_RESET
        << COLOR_WHITE << "[ "
        << scoreColor;

    for (int i = 0; i < filledBlocks; i++)
        cout << static_cast<char>(219);

    cout << COLOR_WHITE;

    for (int i = filledBlocks; i < barLength; i++)
        cout << static_cast<char>(176);

    cout << " ] "
        << scoreColor
        << right << setw(3) << score << "%"
        << COLOR_RESET;

    int usedLength = 2 + labelWidth + 2 + barLength + 3 + 4;
    int remainingSpace = width - usedLength;

    if (remainingSpace < 0) remainingSpace = 0;

    cout << string(remainingSpace, ' ')
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";
}

// Animated loading bar that stays inside the attack box.
static void showBoxedLoadingStep(
    const string& message,
    int width = ATTACK_BOX_WIDTH)
{
    const int messageWidth = 20;
    const int barLength = 20;

    for (int progress = 0; progress <= barLength; progress++)
    {
        int percentage = (progress * 100) / barLength;

        cout << "\r"
            << COLOR_WHITE << "|  "
            << COLOR_CYAN
            << left << setw(messageWidth) << message
            << COLOR_RESET
            << COLOR_WHITE << "[ "
            << COLOR_GREEN;

        for (int i = 0; i < progress; i++)
            cout << static_cast<char>(219);

        cout << COLOR_WHITE;

        for (int i = progress; i < barLength; i++)
            cout << static_cast<char>(176);

        cout << " ] "
            << right << setw(3) << percentage << "%";

        if (progress == barLength)
            cout << COLOR_GREEN << "  [OK]" << COLOR_RESET;
        else
            cout << "      ";

        cout << " "
            << COLOR_WHITE << "|"
            << COLOR_RESET;

        cout.flush();
        this_thread::sleep_for(chrono::milliseconds(35));
    }

    cout << "\n";
}

// ============================================================
// ATTACK DISPLAY HEADER
// ============================================================

static void printSimulationHeader(
    const string& number,
    const string& attackName,
    const string& description)
{
    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        number + "  " + attackName,
        COLOR_CYAN);

    printAttackBorder();

    printAttackEmptyRow();

    printWrappedAttackText(
        description,
        COLOR_WHITE);

    printAttackEmptyRow();
}

// ============================================================
// DICTIONARY ATTACK
// ============================================================

static void simulateDictionaryAttack(
    const PasswordAnalysis& analysis,
    const string& crackTime)
{
    printSimulationHeader(
        "01",
        "DICTIONARY ATTACK",
        "Testing common passwords, known words, and leaked password lists.");

    showBoxedLoadingStep("Testing wordlist");

    printAttackEmptyRow();
    printAttackBorder();

    if (analysis.isCommonPassword ||
        analysis.isDictionaryWord)
    {
        printAttackFieldRow(
            "Result",
            "VULNERABLE",
            COLOR_RED);

        printAttackFieldRow(
            "Match Found",
            "Yes",
            COLOR_RED);

        printAttackFieldRow(
            "Estimated Time",
            crackTime,
            COLOR_RED);

        printAttackFieldRow(
            "Risk Level",
            "CRITICAL",
            COLOR_RED);
    }
    else
    {
        printAttackFieldRow(
            "Result",
            "RESISTED",
            COLOR_GREEN);

        printAttackFieldRow(
            "Match Found",
            "No dictionary match",
            COLOR_GREEN);

        printAttackFieldRow(
            "Estimated Time",
            crackTime,
            COLOR_WHITE);

        printAttackFieldRow(
            "Risk Level",
            "LOW",
            COLOR_GREEN);
    }

    printAttackBorder();
}

// ============================================================
// HYBRID ATTACK
// ============================================================

static void simulateHybridAttack(
    const PasswordAnalysis& analysis,
    const string& crackTime)
{
    printSimulationHeader(
        "02",
        "HYBRID ATTACK",
        "Testing dictionary words with numbers, symbols, capitalization, and common mutations.");

    showBoxedLoadingStep("Testing mutations");

    printAttackEmptyRow();
    printAttackBorder();

    if (analysis.isDictionaryWord ||
        analysis.hasPredictableSubstitution ||
        analysis.hasWeakSuffix)
    {
        printAttackFieldRow(
            "Result",
            "VULNERABLE",
            COLOR_RED);

        printAttackFieldRow(
            "Pattern Found",
            "Predictable mutation",
            COLOR_RED);

        printAttackFieldRow(
            "Estimated Time",
            crackTime,
            COLOR_RED);

        printAttackFieldRow(
            "Risk Level",
            "HIGH",
            COLOR_RED);
    }
    else
    {
        printAttackFieldRow(
            "Result",
            "RESISTED",
            COLOR_GREEN);

        printAttackFieldRow(
            "Pattern Found",
            "No obvious mutation",
            COLOR_GREEN);

        printAttackFieldRow(
            "Estimated Time",
            crackTime,
            COLOR_WHITE);

        printAttackFieldRow(
            "Risk Level",
            "LOW-MEDIUM",
            COLOR_CYAN);
    }

    printAttackBorder();
}

// ============================================================
// RAINBOW TABLE ATTACK
// ============================================================

static void simulateRainbowTable()
{
    printSimulationHeader(
        "03",
        "RAINBOW TABLE ATTACK",
        "Searching precomputed password-hash tables for a matching value.");

    showBoxedLoadingStep("Searching tables");

    printAttackEmptyRow();
    printAttackBorder();

    printAttackFieldRow(
        "Result",
        "BLOCKED BY SALTING",
        COLOR_GREEN);

    printAttackFieldRow(
        "Vulnerable If",
        "Hash is unsalted",
        COLOR_YELLOW);

    printAttackFieldRow(
        "Protection",
        "Unique hash salt",
        COLOR_GREEN);

    printAttackFieldRow(
        "Risk Level",
        "LOW",
        COLOR_GREEN);

    printAttackEmptyRow();

    printWrappedAttackText(
        "Rainbow tables are ineffective when a modern system stores every password using a unique cryptographic salt.",
        COLOR_WHITE);

    printAttackBorder();
}

// ============================================================
// GPU BRUTE-FORCE ATTACK
// ============================================================

static void simulateGpuBruteForce(
    const string& crackTime,
    int securityScore)
{
    printSimulationHeader(
        "04",
        "GPU BRUTE FORCE ATTACK",
        "Testing possible password combinations using simulated dedicated GPU hardware.");

    showBoxedLoadingStep("Running GPU rig");

    printAttackEmptyRow();
    printAttackBorder();

    string riskLevel =
        getAttackRiskLevel(securityScore);

    string riskColor =
        getAttackRiskColor(riskLevel);

    printAttackFieldRow(
        "Method",
        "GPU combination search",
        COLOR_WHITE);

    printAttackFieldRow(
        "Result",
        "CRACK TIME ESTIMATED",
        COLOR_YELLOW);

    printAttackFieldRow(
        "Estimated Time",
        crackTime,
        riskColor);

    printAttackFieldRow(
        "Risk Level",
        riskLevel,
        riskColor);

    printAttackBorder();
}

// ============================================================
// STANDARD BRUTE-FORCE ATTACK
// ============================================================

static void simulateBruteForce(
    const string& crackTime,
    int securityScore)
{
    printSimulationHeader(
        "05",
        "STANDARD BRUTE FORCE ATTACK",
        "Testing every possible password combination using simulated standard hardware.");

    showBoxedLoadingStep("Testing combinations");

    printAttackEmptyRow();
    printAttackBorder();

    string riskLevel =
        getAttackRiskLevel(securityScore);

    string riskColor =
        getAttackRiskColor(riskLevel);

    printAttackFieldRow(
        "Method",
        "Complete combination search",
        COLOR_WHITE);

    printAttackFieldRow(
        "Result",
        "CRACK TIME ESTIMATED",
        COLOR_YELLOW);

    printAttackFieldRow(
        "Estimated Time",
        crackTime,
        riskColor);

    printAttackFieldRow(
        "Risk Level",
        riskLevel,
        riskColor);

    printAttackBorder();
}

// ============================================================
// FASTEST ATTACK
// ============================================================

// Selects the attack that is most likely to succeed first.
static string getFastestAttackName(
    const PasswordAnalysis& analysis)
{
    if (analysis.isCommonPassword ||
        analysis.isDictionaryWord)
    {
        return "Dictionary Attack";
    }

    if (analysis.hasPredictableSubstitution ||
        analysis.hasWeakSuffix)
    {
        return "Hybrid Attack";
    }

    return "GPU Brute Force";
}

// Returns the estimated time for the fastest applicable attack.
static string getFastestAttackTime(
    const PasswordAnalysis& analysis,
    const CrackTimeEstimates& crackTimes)
{
    if (analysis.isCommonPassword ||
        analysis.isDictionaryWord)
    {
        return crackTimes.dictionaryAttack;
    }

    if (analysis.hasPredictableSubstitution ||
        analysis.hasWeakSuffix)
    {
        return crackTimes.hybridAttack;
    }

    return crackTimes.gpuAttack;
}

// ============================================================
// RESISTANCE SUMMARY
// ============================================================

static void printResistanceSummary(
    const string& password,
    const PasswordAnalysis& analysis,
    double entropyBits,
    const CrackTimeEstimates& crackTimes)
{
    int score =
        calculateSecurityScore(
            analysis,
            entropyBits);

    string resistanceLabel =
        getResistanceLabel(score);

    string threatLevel =
        getThreatLevel(score);

    string threatColor =
        getThreatLevelColor(threatLevel);

    string fastestAttack =
        getFastestAttackName(analysis);

    string fastestTime =
        getFastestAttackTime(
            analysis,
            crackTimes);

    int characterVariety =
        countCharacterVariety(password);

    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        "RESISTANCE SUMMARY",
        COLOR_YELLOW);

    printAttackBorder();

    printAttackEmptyRow();

    printAttackFieldRow(
        "Password Length",
        to_string(password.length()) + " characters",
        COLOR_WHITE);

    printAttackFieldRow(
        "Character Variety",
        to_string(characterVariety) + " of 4",
        characterVariety == 4
        ? COLOR_GREEN
        : COLOR_YELLOW);

    printAttackFieldRow(
        "Fastest Attack",
        fastestAttack,
        COLOR_RED);

    printAttackFieldRow(
        "Fastest Crack Time",
        fastestTime,
        COLOR_YELLOW);

    printAttackEmptyRow();

    printAttackFieldRow(
        "Resistance Score",
        to_string(score) + " / 100",
        getScoreColor(score));

    printAttackFieldRow(
        "Overall Rating",
        resistanceLabel,
        getScoreColor(score));

    printAttackFieldRow(
        "Threat Level",
        threatLevel,
        threatColor);

    printAttackEmptyRow();

    printResistanceBar(score);

    printAttackEmptyRow();

    printAttackBorder();
}

// ============================================================
// SECURITY RECOMMENDATIONS
// ============================================================

static void printAttackRecommendations(
    const string& password,
    const PasswordAnalysis& analysis)
{
    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        "SECURITY RECOMMENDATION",
        COLOR_YELLOW);

    printAttackBorder();

    printAttackEmptyRow();

    if (password.length() < 14)
    {
        printWrappedAttackText(
            "Increase the password length to at least 14 characters.",
            COLOR_YELLOW);
    }
    else
    {
        printWrappedAttackText(
            "Your password length provides better resistance against brute-force attacks.",
            COLOR_GREEN);
    }

    if (analysis.isCommonPassword ||
        analysis.isDictionaryWord)
    {
        printWrappedAttackText(
            "Avoid common words, leaked passwords, names, and dictionary-based passwords.",
            COLOR_RED);
    }

    if (analysis.hasPredictableSubstitution ||
        analysis.hasWeakSuffix)
    {
        printWrappedAttackText(
            "Avoid predictable substitutions and weak endings such as names, dates, or repeated numbers.",
            COLOR_YELLOW);
    }

    printWrappedAttackText(
        "Use a unique random password or a long passphrase for every important account.",
        COLOR_WHITE);

    printWrappedAttackText(
        "Enable multi-factor authentication whenever it is available.",
        COLOR_CYAN);

    printAttackEmptyRow();

    printAttackBorder();
}

// ============================================================
// EDUCATIONAL NOTE
// ============================================================

static void printEducationalNote()
{
    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        "EDUCATIONAL NOTE",
        COLOR_CYAN);

    printAttackBorder();

    printAttackEmptyRow();

    printWrappedAttackText(
        "Real attackers may combine dictionary, hybrid, and brute-force techniques and run them in parallel.",
        COLOR_WHITE);

    printWrappedAttackText(
        "A password must resist the fastest attack that successfully applies to it.",
        COLOR_WHITE);

    printWrappedAttackText(
        "Password length and true randomness provide stronger protection than predictable complexity tricks.",
        COLOR_YELLOW);

    printAttackEmptyRow();

    printAttackBorder();
}

// ============================================================
// ATTACK MENU
// ============================================================

static void printAttackSelectionMenu()
{
    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        "SELECT ATTACK",
        COLOR_CYAN);

    printAttackBorder();

    printAttackEmptyRow();

    printAttackTextRow(
        "[1] Dictionary Attack");

    printAttackTextRow(
        "[2] Hybrid Attack");

    printAttackTextRow(
        "[3] Rainbow Table Attack");

    printAttackTextRow(
        "[4] GPU Brute Force Attack");

    printAttackTextRow(
        "[5] Standard Brute Force Attack");

    printAttackTextRow(
        "[6] Run All Simulations",
        COLOR_YELLOW);

    printAttackEmptyRow();

    printAttackBorder();
}

// ============================================================
// MAIN ATTACK SIMULATOR
// ============================================================

void attackSimulatorMenu()
{
    string password;

    cout << "\n";

    printAttackBorder();

    printAttackTitleRow(
        "ATTACK SIMULATOR",
        COLOR_CYAN);

    printAttackTitleRow(
        "EDUCATIONAL MODE",
        COLOR_YELLOW);

    printAttackBorder();

    printAttackEmptyRow();

    printWrappedAttackText(
        "This module demonstrates how common password attacks work.",
        COLOR_WHITE);

    printWrappedAttackText(
        "No real systems, accounts, networks, or devices are targeted.",
        COLOR_GREEN);

    printAttackEmptyRow();

    printAttackBorder();

    cout << "\nEnter password to test: ";

    cin >> password;

    PasswordAnalysis analysis =
        analyzePassword(password);

    double entropyBits =
        calculateEntropyBits(password);

    CrackTimeEstimates crackTimes =
        estimateCrackTimes(
            entropyBits,
            analysis.isDictionaryWord,
            analysis.isCommonPassword);

    int securityScore =
        calculateSecurityScore(
            analysis,
            entropyBits);

    printAttackSelectionMenu();

    cout << "\nEnter choice: ";

    int choice;
    cin >> choice;

    switch (choice)
    {
    case 1:
        simulateDictionaryAttack(
            analysis,
            crackTimes.dictionaryAttack);
        break;

    case 2:
        simulateHybridAttack(
            analysis,
            crackTimes.hybridAttack);
        break;

    case 3:
        simulateRainbowTable();
        break;

    case 4:
        simulateGpuBruteForce(
            crackTimes.gpuAttack,
            securityScore);
        break;

    case 5:
        simulateBruteForce(
            crackTimes.bruteForceAttack,
            securityScore);
        break;

    case 6:
        cout << "\n";

        printAttackBorder();

        printAttackTitleRow(
            "ATTACK SIMULATION REPORT",
            COLOR_YELLOW);

        printAttackBorder();

        simulateDictionaryAttack(
            analysis,
            crackTimes.dictionaryAttack);

        simulateHybridAttack(
            analysis,
            crackTimes.hybridAttack);

        simulateRainbowTable();

        simulateGpuBruteForce(
            crackTimes.gpuAttack,
            securityScore);

        simulateBruteForce(
            crackTimes.bruteForceAttack,
            securityScore);
        break;

    default:
        cout << "\n"
            << COLOR_YELLOW
            << "Invalid choice. Please select an option from 1 to 6."
            << COLOR_RESET
            << "\n";

        printFooter();
        return;
    }

    printResistanceSummary(
        password,
        analysis,
        entropyBits,
        crackTimes);

    printAttackRecommendations(
        password,
        analysis);

    printEducationalNote();
}