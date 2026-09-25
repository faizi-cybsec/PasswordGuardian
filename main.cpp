/*
    ============================================================
    PASSWORD GUARDIAN PRO
    AI Password Security Analyzer
    ============================================================

    Programming Fundamentals Course Project
    Department : BS Cyber Security
    Developer  : Faizan Ahmed
    University : Superior University

    This is the polished "Pro" version of the original Password
    Guardian project. Every core feature has been kept and
    upgraded, and the console UI has been made consistent from
    screen to screen so the program feels like a single piece of
    professional security software:
      - Password Strength Analyzer (deep pattern analysis, real
        entropy, a weighted 0-100 score, letter grade, strength
        label, threat level, and an AI explanation engine that
        explains WHY a password scored the way it did)
      - Password Generator (Easy/Medium/Strong/Military/Custom,
        shown inside a bordered box with an immediate analysis)
      - Have I Been Pwned breach check (SHA-1 + k-Anonymity)
      - An educational (non-real) Attack Simulator
      - A random cybersecurity tip on every launch

    Technologies used:
      - C++17 (basic console I/O, strings, arrays, loops, vectors)
      - A hand-written SHA-1 hashing function (unchanged from v1)
      - The system "curl" command to talk to the internet
      - The Have I Been Pwned Password API (k-Anonymity model)

    ============================================================
*/
#include <iomanip>
#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

#include "Utils.h"
#include "PasswordAnalyzer.h"
#include "Entropy.h"
#include "PasswordGenerator.h"
#include "HIBP.h"
#include "AttackSimulator.h"

using namespace std;

// ==============================================================
// SECTION 1: BANNER AND STARTUP SCREEN
// ==============================================================

// Prints the startup banner. The ASCII art title is stored as a
// raw string literal (R"( ... )") so the backslashes used to draw
// the letters do not need to be escaped one by one. This is the
// SAME banner as the original Password Guardian project.
void showBanner()
{
    // ---- ASCII art title: "PASSWORD" / "GUARDIAN" (cyan) ----
    cout << COLOR_CYAN << R"(
              ____   _    ____ ______        _____  ____  ____
             |  _ \ / \  / ___/ ___\ \      / / _ \|  _ \|  _ \
             | |_) / _ \ \___ \___ \\ \ /\ / / | | | |_) | | | |
             |  __/ ___ \ ___) |__) |\ V  V /| |_| |  _ <| |_| |
             |_| /_/   \_\____/____/  \_/\_/  \___/|_| \_\____/

               ____ _   _   _    ____  ____ ___    _    _   _
              / ___| | | | / \  |  _ \|  _ \_ _|  / \  | \ | |
             | |  _| | | |/ _ \ | |_) | | | | |  / _ \ |  \| |
             | |_| | |_| / ___ \|  _ <| |_| | | / ___ \| |\  |
              \____|\___/_/   \_\_| \_\____/___/_/   \_\_| \_|
)" << COLOR_RESET;

    // ---- Subtitle (yellow) ----
    cout << COLOR_YELLOW << R"(
          -- AI Password Security Analyzer --
)" << COLOR_RESET;
    printLine();
}

// Shows a professional-looking startup information panel: version,
// developer, university, project name, modules loaded and API
// status, followed by an animated module-loading sequence and a
// random cybersecurity tip. This is the FIRST thing the user sees
// after the banner, so it sets the tone for the whole program.
void showStartupInfo()
{
    printRow("Project", "Password Guardian");
    printRow("System Status", COLOR_GREEN + std::string("[ONLINE]") + COLOR_RESET);
	printRow("Mode", "Educational");
    printRow("Current Time", getCurrentDateString() + "  " + getCurrentTimeString());

    cout << "\n";
    printLine();
    cout << COLOR_CYAN
        << R"([                     SYSTEM MODULES                       ])"
        << COLOR_RESET << "\n";
    printLine();
    cout << "\n";

    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET
        << "      Password Analyzer\n";

    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET
        << "      Entropy Engine\n";

    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET
        << "      Password Generator\n";

    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET
        << "      Attack Simulator\n";

    cout << "  " << COLOR_GREEN << "[ONLINE]" << COLOR_RESET
        << "  HIBP API Integration\n";

    // printSection("INITIALIZING PASSWORD GUARDIAN ");
    cout << "\n";
    printLine();

    cout << COLOR_YELLOW
        << R"(              INITIALIZING PASSWORD GUARDIAN)"
        << COLOR_RESET << "\n";

    printLine();
    cout << COLOR_RESET;
    cout << "\n";

    // A single reusable animated bar (Utils::showLoadingStep) is
    // called once per module, so every "loading" moment in the
    // program shares the exact same look and feel.
    static const string loadSteps[] = {
        "Password Analyzer",
        "Entropy Engine",
        "Password Generator",
        "HIBP API Integration",
        "Attack Simulator",
        "Dictionary Database"
    };

    int stepCount = sizeof(loadSteps) / sizeof(loadSteps[0]);

    for (int i = 0; i < stepCount; i++)
    {
        showLoadingStep(loadSteps[i]);

        // Adds one blank line between module rows
        if (i < stepCount - 1)
        {
            cout << "\n";
        }
    }

    cout << "\n\nAll modules initialized successfully. "
        << COLOR_GREEN << "[OK]"
        << COLOR_RESET << "\n\n";
}

// Centers text inside a fixed-width box row.
static string centerTipText(
    const string& text,
    int width
)
{
    if (static_cast<int>(text.length()) >= width)
    {
        return text.substr(0, width);
    }

    int spaces =
        width - static_cast<int>(text.length());

    int leftSpaces = spaces / 2;
    int rightSpaces = spaces - leftSpaces;

    return string(leftSpaces, ' ')
        + text
        + string(rightSpaces, ' ');
}

// Prints the top, divider, or bottom border.
static void printTipBorder(int width)
{
    cout << COLOR_WHITE
        << "  +"
        << string(width, '-')
        << "+"
        << COLOR_RESET
        << "\n";
}

// Prints an empty row without breaking the box.
static void printTipEmptyRow(int width)
{
    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << string(width, ' ')
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a centered colored title row.
static void printTipTitleRow(
    const string& title,
    int width,
    const string& color
)
{
    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << color
        << centerTipText(title, width)
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints one numbered security recommendation.
static void printSecurityTipRow(
    const string& number,
    const string& message,
    int width,
    const string& messageColor
)
{
    const int contentWidth = width - 4;

    string numberText = "[" + number + "]";
    string fullText = numberText + " " + message;

    if (static_cast<int>(fullText.length()) > contentWidth)
    {
        fullText =
            fullText.substr(0, contentWidth);
    }

    int remainingSpaces =
        contentWidth -
        static_cast<int>(numberText.length()) -
        1 -
        static_cast<int>(message.length());

    if (remainingSpaces < 0)
    {
        remainingSpaces = 0;
    }

    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << "  "
        << COLOR_CYAN
        << numberText
        << COLOR_RESET
        << " "
        << messageColor
        << message
        << COLOR_RESET
        << string(remainingSpaces, ' ')
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a normal colored text row.
static void printTipTextRow(
    const string& text,
    int width,
    const string& color
)
{
    const int contentWidth = width - 4;

    string shownText = text;

    if (static_cast<int>(shownText.length()) > contentWidth)
    {
        shownText =
            shownText.substr(0, contentWidth);
    }

    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << "  "
        << color
        << left
        << setw(contentWidth)
        << shownText
        << COLOR_RESET
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// ==============================================================
// SECTION 2: MAIN MENU
// ==============================================================

void showMenu()
{
    cout << "\n";
    cout << COLOR_BLUE;
    printLine();
    cout << "                         MAIN MENU\n";
    printLine();
    cout << COLOR_RESET;

    cout << "  " << COLOR_CYAN << "[1]" << COLOR_RESET << "  Analyze Password\n";
    cout << "  " << COLOR_CYAN << "[2]" << COLOR_RESET << "  Generate Password\n";
    cout << "  " << COLOR_CYAN << "[3]" << COLOR_RESET << "  Breach Database\n";
    cout << "  " << COLOR_CYAN << "[4]" << COLOR_RESET << "  Attack Simulator (Educational)\n";
    cout << "  " << COLOR_CYAN << "[5]" << COLOR_RESET << "  Security Tips\n";
    cout << "  " << COLOR_CYAN << "[6]" << COLOR_RESET << "  About\n";
    cout << "  " << COLOR_CYAN << "[0]" << COLOR_RESET << "  Exit\n";

    cout << COLOR_BLUE;
    printLine();
    cout << COLOR_RESET;
    cout << "Enter Choice : ";
}

// ==============================================================
// SECTION 3: MENU HANDLERS
// ==============================================================

// [1] Analyze Password - runs the full dashboard
void handleAnalyzePassword()
{
    string password;
    cout << "\nEnter password to analyze: ";
    cin >> password;

    PasswordAnalysis analysis = analyzePassword(password);
    printPasswordDashboard(analysis);
}

// [5] Security Tips - kept from the original project's recommendations page
void showSecurityRecommendations()
{
    const int boxWidth = 54;

    cout << "\n";

    // ============================================================
    // MAIN HEADER
    // ============================================================

    printTipBorder(boxWidth);

    printTipTitleRow(
        "SECURITY TIPS",
        boxWidth,
        COLOR_CYAN
    );

    printTipTitleRow(
        "Practical Password Safety Guidance",
        boxWidth,
        COLOR_YELLOW
    );

    printTipBorder(boxWidth);

    // ============================================================
    // CORE PROTECTION
    // ============================================================

    cout << "\n";

    printTipBorder(boxWidth);

    printTipTitleRow(
        "CORE PROTECTION",
        boxWidth,
        COLOR_CYAN
    );

    printTipBorder(boxWidth);
    printTipEmptyRow(boxWidth);

    printSecurityTipRow(
        "01",
        "Use at least 12 characters",
        boxWidth,
        COLOR_GREEN
    );

    printTipEmptyRow(boxWidth);

    printSecurityTipRow(
        "02",
        "Mix letters, numbers, and symbols",
        boxWidth,
        COLOR_GREEN
    );

    printTipEmptyRow(boxWidth);

    printSecurityTipRow(
        "03",
        "Avoid names, dates, and dictionary words",
        boxWidth,
        COLOR_YELLOW
    );

    printTipEmptyRow(boxWidth);

    printSecurityTipRow(
        "04",
        "Never reuse passwords across accounts",
        boxWidth,
        COLOR_RED
    );

    printTipEmptyRow(boxWidth);

    printSecurityTipRow(
        "05",
        "Enable Multi-Factor Authentication",
        boxWidth,
        COLOR_GREEN
    );

    printTipEmptyRow(boxWidth);
    printTipBorder(boxWidth);

    // ============================================================
    // BEST PRACTICE
    // ============================================================

    cout << "\n";

    printTipBorder(boxWidth);

    printTipTitleRow(
        "BEST PRACTICE",
        boxWidth,
        COLOR_CYAN
    );

    printTipBorder(boxWidth);
    printTipEmptyRow(boxWidth);

    printTipTextRow(
        "Use a trusted password manager to create and store",
        boxWidth,
        COLOR_YELLOW
    );

    printTipTextRow(
        "unique passwords for every account.",
        boxWidth,
        COLOR_GREEN
    );

    printTipEmptyRow(boxWidth);
    printTipBorder(boxWidth);

    // ============================================================
    // RANDOM CYBER FACT
    // ============================================================

    cout << "\n";

    cout << COLOR_CYAN
        << "  [ -- DID YOU KNOW? -- ]"
        << COLOR_RESET
        << "\n";

    cout << COLOR_WHITE
        << "  "
        << string(49, '-')
        << COLOR_RESET
        << "\n\n";

    printRandomCyberTip();
}

// ============================================================
// ABOUT SECTION DISPLAY HELPERS
// ============================================================

static const int ABOUT_BOX_WIDTH = 58;

static string centerAboutText(const string& text, int width)
{
    if (static_cast<int>(text.length()) >= width)
        return text.substr(0, width);

    int totalSpace = width - static_cast<int>(text.length());
    int leftSpace = totalSpace / 2;
    int rightSpace = totalSpace - leftSpace;

    return string(leftSpace, ' ') +
        text +
        string(rightSpace, ' ');
}

static void printAboutBorder(int width = ABOUT_BOX_WIDTH)
{
    cout << COLOR_WHITE
        << "+"
        << string(width, '-')
        << "+"
        << COLOR_RESET
        << "\n";
}

static void printAboutEmptyRow(int width = ABOUT_BOX_WIDTH)
{
    cout << COLOR_WHITE
        << "|"
        << string(width, ' ')
        << "|"
        << COLOR_RESET
        << "\n";
}

static void printAboutTitleRow(
    const string& title,
    const string& color = COLOR_CYAN,
    int width = ABOUT_BOX_WIDTH)
{
    cout << COLOR_WHITE << "|"
        << color
        << centerAboutText(title, width)
        << COLOR_RESET
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";
}

static void printAboutTextRow(
    const string& text,
    const string& color = COLOR_WHITE,
    int width = ABOUT_BOX_WIDTH)
{
    string displayText = text;

    if (static_cast<int>(displayText.length()) > width - 4)
        displayText = displayText.substr(0, width - 4);

    int remainingSpace =
        width - 4 - static_cast<int>(displayText.length());

    cout << COLOR_WHITE << "|  "
        << color
        << displayText
        << string(remainingSpace, ' ')
        << COLOR_RESET
        << COLOR_WHITE << "  |"
        << COLOR_RESET
        << "\n";
}

static void printAboutFieldRow(
    const string& label,
    const string& value,
    const string& valueColor = COLOR_WHITE,
    int width = ABOUT_BOX_WIDTH)
{
    const int labelWidth = 18;

    string displayLabel = label;
    string displayValue = value;

    if (static_cast<int>(displayLabel.length()) > labelWidth)
        displayLabel = displayLabel.substr(0, labelWidth);

    int maximumValueLength =
        width - 2 - labelWidth - 3;

    if (static_cast<int>(displayValue.length()) >
        maximumValueLength)
    {
        displayValue =
            displayValue.substr(0, maximumValueLength);
    }

    int usedLength =
        2 +
        labelWidth +
        3 +
        static_cast<int>(displayValue.length());

    int remainingSpace = width - usedLength;

    if (remainingSpace < 0)
        remainingSpace = 0;

    cout << COLOR_WHITE << "|  "
        << COLOR_CYAN
        << left << setw(labelWidth) << displayLabel
        << COLOR_RESET
        << COLOR_WHITE << " : "
        << valueColor
        << displayValue
        << COLOR_RESET
        << string(remainingSpace, ' ')
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";
}

static void printWrappedAboutText(
    const string& text,
    const string& color = COLOR_WHITE,
    int width = ABOUT_BOX_WIDTH)
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

        string line =
            text.substr(position, take);

        printAboutTextRow(line, color, width);

        position += take;

        while (position < text.length() &&
            text[position] == ' ')
        {
            position++;
        }
    }
}

static void printAboutBullet(
    const string& text,
    const string& color = COLOR_WHITE)
{
    printWrappedAboutText(
        "- " + text,
        color);
}

// ============================================================
// [6] ABOUT PASSWORD GUARDIAN
// ============================================================

void showAbout()
{
    cout << "\n";

    // Main heading
    printAboutBorder();

    printAboutTitleRow(
        "ABOUT PASSWORD GUARDIAN",
        COLOR_CYAN);

    printAboutTitleRow(
        "PROJECT PROFILE",
        COLOR_YELLOW);

    printAboutBorder();

    printAboutEmptyRow();

    printWrappedAboutText(
        "Password Guardian is an Educational C++ cybersecurity application designed to Analyze, Generate, Test, and Protect passwords through practical security tools.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();

    // Project information
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "PROJECT INFORMATION",
        COLOR_CYAN);

    printAboutBorder();

    printAboutFieldRow(
        "Project Name",
        "Password Guardian",
        COLOR_GREEN);

    printAboutFieldRow(
        "Project Type",
        "Password Security Tool",
        COLOR_WHITE);

    printAboutFieldRow(
        "University",
        "Superior University",
        COLOR_WHITE);

    printAboutFieldRow(
        "Program",
        "BS Cyber Security",
        COLOR_WHITE);

    printAboutFieldRow(
        "Language",
        "C++",
        COLOR_YELLOW);

    printAboutBorder();

    // Project scope
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "PROJECT SCOPE",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printWrappedAboutText(
        "The project focuses on password security Awareness, Secure Password creation, Breach Detection, and safe demonstrations of common password Attacks.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();

    // Core technologies
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "CORE TECHNOLOGIES",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printAboutTextRow(
        "[01] C++17",
        COLOR_YELLOW);

    printWrappedAboutText(
        "Functions, structs, strings, loops, arrays, vectors, file handling, and modular programming.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[02] SHA-1 HASHING",
        COLOR_YELLOW);

    printWrappedAboutText(
        "A manually implemented hashing algorithm used for privacy-focused breach checking.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[03] HAVE I BEEN PWNED API",
        COLOR_YELLOW);

    printWrappedAboutText(
        "Uses the k-Anonymity model to check breached passwords without sending the complete password.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[04] CONSOLE INTERFACE",
        COLOR_YELLOW);

    printWrappedAboutText(
        "Uses ANSI colors, formatted dashboards, progress bars, and structured security reports.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[05] CURL NETWORK REQUEST",
        COLOR_YELLOW);

    printWrappedAboutText(
        "Uses the system curl command to communicate with the breach-checking API.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();

    // Core features
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "CORE FEATURES",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printAboutTextRow(
        "[1] PASSWORD ANALYZER",
        COLOR_GREEN);

    printWrappedAboutText(
        "Evaluates strength, entropy, patterns, crack time, security score, and recommendations.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[2] PASSWORD GENERATOR",
        COLOR_GREEN);

    printWrappedAboutText(
        "Creates secure random passwords using preset and customizable generation modes.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[3] BREACH CHECKER",
        COLOR_GREEN);

    printWrappedAboutText(
        "Checks passwords against known breach records using SHA-1 hashing and k-Anonymity.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "[4] ATTACK SIMULATOR",
        COLOR_GREEN);

    printWrappedAboutText(
        "Demonstrates dictionary, hybrid, rainbow-table, GPU, and brute-force attacks safely.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();

    // Security principles
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "SECURITY PRINCIPLES",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printAboutBullet(
        "Passwords are never stored by the application.",
        COLOR_GREEN);

    printAboutBullet(
        "Full passwords are not sent during breach checking.",
        COLOR_GREEN);

    printAboutBullet(
        "k-Anonymity helps protect user privacy.",
        COLOR_GREEN);

    printAboutBullet(
        "Attack simulations are educational and non-operational.",
        COLOR_YELLOW);

    printAboutBullet(
        "Strong passwords should be unique, long, and random.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();

    // Educational objectives
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "EDUCATIONAL OBJECTIVES",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printAboutBullet(
        "Apply fundamental C++ programming concepts.");

    printAboutBullet(
        "Practice modular programming across multiple files.");

    printAboutBullet(
        "Understand password entropy and crack-time estimates.");

    printAboutBullet(
        "Explore hashing, APIs, and privacy-focused methods.");

    printAboutBullet(
        "Promote safer password-security practices.");

    printAboutEmptyRow();

    printAboutBorder();

    // Acknowledgements
    cout << "\n";

    printAboutBorder();

    printAboutTitleRow(
        "ACKNOWLEDGEMENTS",
        COLOR_CYAN);

    printAboutBorder();

    printAboutEmptyRow();

    printAboutTextRow(
        "HAVE I BEEN PWNED",
        COLOR_YELLOW);

    printWrappedAboutText(
        "For providing the public Pwned Passwords API used for educational breach checking.",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutTextRow(
        "SUPERIOR UNIVERSITY",
        COLOR_YELLOW);

    printWrappedAboutText(
        "BS Cyber Security Program",
        COLOR_WHITE);

    printAboutEmptyRow();

    printAboutBorder();
}

// ==============================================================
// SECTION 4: PROGRAM ENTRY POINT
// ==============================================================

int main()
{
    // Seed the random number generator once at the start
    srand((unsigned int)time(0));

    showBanner();
    showStartupInfo();

    int choice;

    do
    {
        showMenu();
        cin >> choice;

        switch (choice)
        {
        case 1:
            handleAnalyzePassword();
            pauseScreen();
            break;
        case 2:
            passwordGeneratorMenu();
            pauseScreen();
            break;
        case 3:
            checkBreachDatabase();
            pauseScreen();
            break;
        case 4:
            attackSimulatorMenu();
            pauseScreen();
            break;
        case 5:
            showSecurityRecommendations();
            pauseScreen();
            break;
        case 6:
            showAbout();
            pauseScreen();
            break;
        case 0:
            cout << "\n" << COLOR_GREEN
                 << "Thank you for using Password Guardian Pro. Stay safe online!"
                 << COLOR_RESET << "\n";
            break;
        default:
            cout << "\n" << COLOR_YELLOW
                 << "Invalid choice. Please try again."
                 << COLOR_RESET << "\n";
            break;
        }

    } while (choice != 0);

    return 0;
}
