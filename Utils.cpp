/*
    ============================================================
    UTILS.CPP
    ============================================================
    Password Guardian Pro — UI & Console Foundation Engine

    Provides central UI layout constants, ANSI color definitions,
    formatting utilities, divider generators, aligned report rows,
    a reusable animated loading bar, and a cybersecurity tip library.
    ============================================================
*/

#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstdlib>

using namespace std;

// ==============================================================
// 1. LAYOUT & UI DIMENSION CONSTANTS
// ==============================================================
// All UI measurements and layout parameters are centralized here
// to ensure perfect console alignment across every screen.
static const int CONSOLE_WIDTH = 60;  // Standard width for titles and dividers
static const int ROW_LABEL_WIDTH = 22;  // Label column width used by printRow()
static const int BAR_LABEL_WIDTH = 18;  // Label column width used by buildProgressBar()
static const int PROGRESS_BAR_WIDTH = 20;  // Fill character width for static result bars
static const int LOADING_BAR_WIDTH = 20;  // Fill character width for animated loading bar
static const int LOADING_LABEL_WIDTH = 32;  // Label column width used by showLoadingStep()
static const int LOADING_STEP_PERCENT = 2;   // Percentage increment per animation frame
static const long ANIMATION_DELAY_TICKS = 20000000; // Delay ticks per frame (smooth & fast)

// ==============================================================
// 2. CONSOLE COLOR DEFINITIONS
// ==============================================================
// Standard ANSI escape sequences for cross-platform console coloring.
const string COLOR_RESET = "\033[0m";
const string COLOR_GREEN = "\033[32m";
const string COLOR_YELLOW = "\033[33m";
const string COLOR_RED = "\033[31m";
const string COLOR_BLUE = "\033[34m";
const string COLOR_CYAN = "\033[36m";
const string COLOR_WHITE = "\033[37m";
const string COLOR_MAGENTA = "\033[35m";
const string COLOR_GRAY = "\033[90m";

// ==============================================================
// 3. DIVIDER LINES
// ==============================================================
// Heavy separator line exported globally for title framing.
const string LINE = string(CONSOLE_WIDTH, '=');

// Light separator line used internally for sub-sections.
static const string THIN_LINE = string(CONSOLE_WIDTH, '-');

// ==============================================================
// 4. DIVIDER HELPER FUNCTIONS
// ==============================================================

// Prints a full-width heavy separator line ('=')
void printLine()
{
    cout << LINE << "\n";
}

// Prints a full-width light separator line ('-')
void printThinLine()
{
    cout << THIN_LINE << "\n";
}

// ==============================================================
// 5. INTERNAL STATUS BADGE & TAG HELPERS
// ==============================================================

// Internal helper to format and print colored status tags cleanly.
// Example output: "  [OK]  Label" or "  [INFO]  Message"
static void printStatusTag(const string& color, const string& tag, const string& label)
{
    cout << "  " << color << "[" << tag << "]" << COLOR_RESET << "  " << label << "\n";
}

// ==============================================================
// 6. PUBLIC UI FORMATTING & SCREEN HELPERS
// ==============================================================

// Prints a page title centered and framed by heavy separator lines.
// Example:
//   ============================================================
//                         PASSWORD REPORT
//   ============================================================
void printTitle(const string& title)
{
    printLine();

    const int titleSize = static_cast<std::string::size_type>(title.size());
    const int availableSpace = CONSOLE_WIDTH - titleSize;
    const int leftPadding = (availableSpace > 0) ? (availableSpace / 2) : 0;

    cout << string(leftPadding, ' ') << COLOR_CYAN << title << COLOR_RESET << "\n";
    printLine();
}

// Prints a formatted key-value row as "label : value" with clean alignment.
// Labels exceeding ROW_LABEL_WIDTH still retain space before the colon.
void printRow(const string& label, const string& value)
{
    cout << label;

    int padding = ROW_LABEL_WIDTH - static_cast<int>(label.size());
    if (padding < 1)
    {
        padding = 1;
    }

    cout << string(padding, ' ') << ": " << value << "\n";
}

// Prints a clean sub-section heading inside reports and screen views.
void printSection(const string& label)
{
    cout << "\n" << COLOR_WHITE << "/// " << label << " ///" << COLOR_RESET << "\n";
}

// Prints a checklist row preceded by a colored [OK] or [NO] tag.
void printCheckRow(bool passed, const string& label)
{
    if (passed)
    {
        printStatusTag(COLOR_GREEN, "OK", label);
    }
    else
    {
        printStatusTag(COLOR_RED, "NO", label);
    }
}

// Prompts the user and waits for Enter before proceeding.
void pauseScreen()
{
    cout << "\nPress Enter to return to Main Menu...";
    cin.ignore();
    cin.get();
}

// Prints the consistent branding block at the bottom of every screen.
void printFooter()
{
    cout << "\n";
    printLine();
    cout << COLOR_CYAN << "Password Guardian Pro v2.0" << COLOR_RESET << "\n";
    cout << "Developed by Faizan Ahmad\n";
    cout << "Superior University\n";
    printLine();
}

// Displays text inside an ASCII box to visually highlight important output.
void printBox(const vector<string>& lines)
{
    size_t maxLen = 0;
    for (size_t i = 0; i < lines.size(); ++i)
    {
        if (lines[i].size() > maxLen)
        {
            maxLen = lines[i].size();
        }
    }

    const string border = "+" + string(maxLen + 2, '-') + "+";

    cout << border << "\n";
    for (size_t i = 0; i < lines.size(); ++i)
    {
        cout << "| " << lines[i] << string(maxLen - lines[i].size(), ' ') << " |\n";
    }
    cout << border << "\n";
}

// Converts a boolean value into "YES" or "NO" string representations.
string yesNo(bool value)
{
    return value ? "YES" : "NO";
}

// Character class checks used by the analyzer and entropy engine.
// These are implemented here to avoid multiple-definition linker
// errors when included across many translation units.
bool hasUppercase(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (password[i] >= 'A' && password[i] <= 'Z') return true;
    }
    return false;
}

bool hasLowercase(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (password[i] >= 'a' && password[i] <= 'z') return true;
    }
    return false;
}

bool hasDigit(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (password[i] >= '0' && password[i] <= '9') return true;
    }
    return false;
}

bool hasSpecialChar(const string& password)
{
    const string specialChars = "!@#$%^&*()-_=+[]{};:,.<>?/|~";
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (specialChars.find(password[i]) != string::npos) return true;
    }
    return false;
}

// ==============================================================
// 7. SCORE COLORING & PROGRESS BAR HELPERS
// ==============================================================

// Selects an ANSI color code based on a 0-100 numerical score.
string getScoreColor(int score)
{
    if (score < 40)
    {
        return COLOR_RED;
    }
    else if (score < 70)
    {
        return COLOR_YELLOW;
    }
    else
    {
        return COLOR_GREEN;
    }
}

// Internal bar frame drawing logic shared by static and animated bars.
// Constructs a bracketed visual fill: [=====>    ]
// Internal bar frame drawing logic shared by static and animated bars.
// Example:
// [██████████>             ]
// [████████████████████████]
static string buildBarFrame(int percent, int width)
{
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    if (width < 1) width = 1;

    int filled = (percent * width) / 100;

    string bar;

    // Left bracket
    bar += COLOR_WHITE;
    bar += "[ ";

    // Filled blocks
    bar += COLOR_GREEN;
    for (int i = 0; i < filled; i++)
        bar += (char)178;

    // Empty blocks
    bar += COLOR_GRAY;
    for (int i = filled; i < width; i++)
        bar += (char)176;


    // Right bracket
    bar += COLOR_WHITE;
    bar += " ]";

    bar += COLOR_RESET;

    return bar;
}
// Builds a static, labeled result bar with perfectly padded percentage text.
// Example: Entropy          [==============>       ]  68%
string buildProgressBar(const string& label, int value, int maxValue)
{
    if (value < 0) value = 0;
    if (value > maxValue) value = maxValue;

    int percent = 0;
    if (maxValue > 0)
    {
        percent = (value * 100) / maxValue;
    }

    int padding = BAR_LABEL_WIDTH - static_cast<int>(label.size());
    if (padding < 1)
    {
        padding = 1;
    }

    ostringstream oss;
    oss << label << string(padding, ' ')
        << buildBarFrame(percent, PROGRESS_BAR_WIDTH) << " "
        << setw(3) << percent << "%";

    return oss.str();
}

// ==============================================================
// 8. ANIMATED LOADING BAR IMPLEMENTATION
// ==============================================================

// Short busy-wait delay to stabilize animation speed across platforms.
static void animationDelay()
{
    for (volatile long i = 0; i < ANIMATION_DELAY_TICKS; ++i)
    {
        // Delay loop
    }
}

// Plays a smooth animated loading sequence.
void showLoadingStep(const string& label)
{
    // Animate from 0% to 100%
    for (int percent = 0; percent <= 100; percent += LOADING_STEP_PERCENT)
    {
        cout << "\r  "
            << left << setw(LOADING_LABEL_WIDTH) << label
            << buildBarFrame(percent, LOADING_BAR_WIDTH)
            << " "
            << right << setw(3) << percent << "%"
            << COLOR_RESET
            << flush;

        animationDelay();
    }

    // Print the completed line once so every module finishes identically
    cout << "\r  "
        << left << setw(LOADING_LABEL_WIDTH) << label
        << buildBarFrame(100, LOADING_BAR_WIDTH)
        << " 100%"
        << COLOR_RESET
        << "  "
        << COLOR_GREEN
        << "[OK]"
        << COLOR_RESET
        << "\n";
}

// ==============================================================
// 9. DATE AND TIME FORMATTING HELPERS
// ==============================================================

// Returns the current system date as "YYYY-MM-DD"
string getCurrentDateString()
{
    time_t now = time(nullptr);
    tm localTime;

#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", &localTime);
    return string(buffer);
}

// Returns the current system time as "HH:MM:SS"
string getCurrentTimeString()
{
    time_t now = time(nullptr);
    tm localTime;

#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &localTime);
    return string(buffer);
}

// ==============================================================
// 10. CYBERSECURITY FACTS DATABASE & TIP HELPERS
// ==============================================================

static const string SECURITY_FACTS[] = {
    "The most commonly used password in the world is still \"123456\".",
    "A 12-character random password can take centuries to brute-force.",
    "Over 80% of hacking-related breaches involve weak or stolen passwords.",
    "Password managers can generate and remember unique passwords for every site.",
    "Multi-Factor Authentication blocks over 99% of automated account attacks.",
    "Reusing the same password on multiple sites multiplies your breach risk.",
    "\"Password123!\" still fails most security audits despite looking complex.",
    "Attackers often try leaked email/password pairs on other websites - this is called credential stuffing.",
    "Dictionary attacks try real words first because people often use them.",
    "Adding just 4 extra random characters can increase crack time by years.",
    "Keyboard patterns like \"qwerty\" or \"asdf\" are among the first guesses attackers try.",
    "Birthdays and anniversaries are common - and predictable - password choices.",
    "The \"k-Anonymity\" model lets you check breaches without exposing your full password.",
    "GPUs can test billions of password guesses per second on stolen hash databases.",
    "Passphrases (multiple random words) can be both strong and easy to remember.",
    "Security questions like \"mother's maiden name\" are often easy to research.",
    "Password entropy measures how unpredictable a password is, in bits.",
    "Two-factor authentication apps are generally safer than SMS codes.",
    "Old breached passwords are still used in attacks years after the breach.",
    "Changing a password after a suspected breach reduces further damage.",
    "Predictable substitutions like \"@\" for \"a\" barely slow down modern crackers.",
    "Password length matters more than complexity for resisting brute force.",
    "Storing passwords in a browser is more convenient but less secure than a dedicated manager.",
    "Hackers use \"rainbow tables\" - precomputed hash lookups - to crack unsalted hashes quickly.",
    "Salting a password hash prevents rainbow table attacks.",
    "Never share your password over email or phone, even with \"IT support\".",
    "Unique passwords per account limit damage if one service is breached.",
    "Public Wi-Fi networks make it easier for attackers to intercept unencrypted logins.",
    "A password with only lowercase letters has far less entropy than a mixed-case one.",
    "Common pet names and sports teams appear frequently in leaked password lists.",
    "Attackers often try a company name plus the current year as a default password guess.",
    "Password spraying tries one common password across many accounts to avoid lockouts.",
    "Biometrics (fingerprint, face ID) can complement, but should not fully replace, passwords.",
    "The average person reuses a password across multiple accounts more than 3 times.",
    "Long random passphrases resist both dictionary and brute-force attacks well.",
    "Security audits often flag passwords under 8 characters as high risk.",
    "Writing passwords on paper stored securely can sometimes be safer than reusing weak ones.",
    "Phishing remains one of the top ways attackers steal passwords, not just cracking them.",
    "Password strength meters can be misleading if they ignore common patterns.",
    "Some breaches go undetected for months before being publicly reported.",
    "A password manager master password should be the strongest password you own.",
    "Attackers automate password guessing with scripts that try thousands of combinations per minute.",
    "Even \"random-looking\" passwords can be weak if humans generated them without true randomness.",
    "Companies are increasingly moving toward passkeys to eliminate passwords entirely.",
    "Repeating a character 3+ times in a row is one of the first patterns crackers check for.",
    "Sequential numbers like \"12345\" appear in millions of leaked password dumps.",
    "Your email password is often the master key to resetting all your other accounts.",
    "Old, unused accounts with weak passwords can still be exploited years later.",
    "Regularly reviewing account activity can help catch unauthorized access early.",
    "The strongest defense against most attacks is a long, unique, randomly generated password.",
    "Security experts recommend changing default router and device passwords immediately.",
    "Hardware security keys (like FIDO2 keys) are among the strongest forms of MFA available.",
    "Password length is exponentially more effective against brute force than adding one more symbol.",
    "\"12345678\" and \"qwerty123\" both regularly appear near the top of leaked password lists.",
    "A dictionary attack can test an entire common wordlist in seconds against an unsalted hash.",
    "Session hijacking can bypass a strong password entirely by stealing an active login token.",
    "Password expiration policies without complexity checks often push users toward weaker patterns.",
    "Typing a password in front of a webcam or in a public place risks \"shoulder surfing\" attacks.",
    "Autofill features are convenient but can leak saved passwords through malicious hidden form fields.",
    "Credential leaks are often bundled and resold on the dark web in bulk for years afterward.",
    "A single reused password can turn one small data breach into access for dozens of accounts.",
    "Security teams recommend at least 16 characters for any account protecting sensitive data.",
    "The word \"admin\" combined with a simple suffix remains one of the most-tried login guesses.",
    "Encrypting a password database at rest protects it even if the storage server itself is compromised.",
    "Attackers frequently test the same password against many sites, hoping for account reuse.",
    "A strong password alone cannot stop phishing - always verify the site before logging in.",
    "Randomly generated passwords are far less predictable than ones humans invent from memory.",
    "Some malware logs every keystroke, capturing passwords no matter how strong they are.",
    "Two accounts with the same password are only as secure as the weaker of the two systems.",
    "Password blacklists block known-breached passwords even if they technically meet complexity rules.",
    "A password that takes a human seconds to type can still take billions of years to brute-force.",
    "Downloadable \"password strength checkers\" that call home over the internet can leak what you type.",
    "Security researchers estimate billions of credential pairs are currently circulating from past breaches.",
    "Locking an account after repeated failed logins slows down - but does not stop - online attacks.",
    "CAPTCHAs are designed to slow automated login attempts, not to replace a strong password.",
    "A memorable passphrase like four random unrelated words can beat a short complex password.",
    "Attackers often start with the smallest, most-guessed password lists before trying anything larger.",
    "Multi-factor authentication protects an account even if the password itself is fully compromised.",
    "Reusing a childhood pet's name is a common - and easily guessed - password habit.",
    "Password managers can flag when a saved password appears in a newly reported data breach.",
    "Storing passwords as plain text in a spreadsheet is one of the least secure habits possible.",
    "Corporate password policies increasingly favor length over forced special-character requirements.",
    "An attacker with GPU hardware can try tens of billions of password guesses every second offline.",
    "A password used only once, for only one account, cannot be reused against you elsewhere.",
    "Security awareness training reduces successful phishing attempts far more than technology alone.",
    "Some websites still store passwords insecurely, so breach notifications should always be taken seriously.",
    "A leaked password hash without a strong hashing algorithm can be cracked far faster than expected.",
    "Bcrypt and Argon2 are deliberately slow hashing algorithms designed to resist brute-force cracking.",
    "Changing just one character in a reused password barely improves its resistance to guessing.",
    "A password vault synced across devices should itself be protected by a very strong master password.",
    "Attackers sometimes buy access to stolen credential databases instead of cracking passwords themselves.",
    "Enabling login alerts can notify you the moment an unfamiliar device accesses your account.",
    "A password containing your username is one of the very first combinations attackers try.",
    "Long, unique passwords cost attackers exponentially more time than short, complex-looking ones.",
    "Security experts recommend rotating only compromised passwords, not all passwords on a fixed schedule.",
    "Many breaches are discovered by security researchers monitoring dark web marketplaces, not by the victim company.",
    "Typing a password into an unfamiliar Wi-Fi login page can itself be a phishing trap.",
    "A password reused across work and personal accounts can turn a personal breach into a corporate one.",
    "Modern operating systems increasingly support passkeys, which cannot be phished the way passwords can.",
    "An attacker only needs one weak password among many strong ones to gain a foothold.",
    "Password history requirements stop users from immediately reusing their last few passwords.",
    "A strong password should never be shared over unencrypted messaging apps or plain text emails.",
    "Randomized password generation tools remove human bias, which is a major source of predictability.",
    "Attackers often target password reset flows, since they can be weaker than the login itself.",
    "Even offline, air-gapped systems benefit from strong passwords in case physical access is ever gained.",
    "A breached password should be treated as permanently compromised, even after it is changed.",
    "Security-conscious teams monitor for typosquatted login pages designed to steal entered passwords."
};

static const int SECURITY_FACT_COUNT = sizeof(SECURITY_FACTS) / sizeof(SECURITY_FACTS[0]);

// Returns a random cybersecurity fact from the fact database.
string getRandomSecurityFact()
{
    int index = rand() % SECURITY_FACT_COUNT;
    return SECURITY_FACTS[index];
}

// Prints a numbered cyber tip using the shared fact database.
void printRandomCyberTip()
{
    int index = rand() % SECURITY_FACT_COUNT;
    cout << COLOR_MAGENTA << "Cyber Tip #" << (index + 1) << COLOR_RESET << "\n";
    cout << "  " << SECURITY_FACTS[index] << "\n";
}