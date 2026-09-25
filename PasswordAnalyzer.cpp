/*
    ============================================================
    PASSWORDANALYZER.CPP
    ============================================================
    Password Guardian Pro — Password Intelligence Engine

    Provides deep pattern scanning, character composition analysis,
    threat scoring, and professional cybersecurity terminal dashboard.
    ============================================================
*/


#include <string>
#include "PasswordAnalyzer.h"
#include "Entropy.h"
#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cctype>

using namespace std;

// NOTE: hasUppercase, hasLowercase, hasDigit, hasSpecialChar
// are defined in Utils.cpp to avoid duplicate symbol errors

// ==============================================================
// DICTIONARIES & PATTERN REPOSITORIES
// ==============================================================

static const string COMMON_PASSWORDS[] = {
    "123456","admin","12345678","123456789","12345","password","aa123456","1234567890","pass@123","admin123","1234567","123123",
    "111111","12345678910","p@ssw0rd","aa@123456","admintelecom","admin@123","112233","000000","password1","password123","password@123",
    "passw0rd","qwerty","qwerty123","qwerty1","qwertyuiop","qwerty12","qwerty12345",
    "abc123",
    "abc123456",
    "1234",
    "123",
    "11111111",
    "1111",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999",
    "654321",
    "987654321",
    "123321",
    "121212",
    "102030",
    "11223344",

    "1q2w3e4r",
    "1q2w3e",
    "1q2w3e4r5t",
    "123qwe",
    "qwe123",
    "qazwsx",
    "zxcvbnm",
    "asdfgh",
    "asdf1234",
    "abcd1234",

    "welcome",
    "welcome123",
    "letmein",
    "login",
    "guest",
    "root",
    "administrator",
    "user",
    "test",
    "test123",

    "iloveyou",
    "hello",
    "hello123",
    "hello123456",
    "monkey",
    "dragon",
    "master",
    "shadow",
    "sunshine",
    "princess",

    "football",
    "baseball",
    "soccer",
    "starwars",
    "superman",
    "batman",
    "freedom",
    "whatever",
    "trustno1",
    "secret",

    "michael",
    "jessica",
    "charlie",
    "donald",
    "ashley",
    "daniel",
    "jordan",
    "pakistan123",
    "skibidi",
    "mustufaj"
};

static const int COMMON_PASSWORD_COUNT =
sizeof(COMMON_PASSWORDS) / sizeof(COMMON_PASSWORDS[0]);

static const string DICTIONARY_WORDS[] = {
    "password", "welcome", "dragon", "monkey", "football", "baseball",
    "master", "shadow", "sunshine", "princess", "login", "admin",
    "letmein", "freedom", "trustno", "whatever", "starwars", "superman",
    "batman", "hello", "computer", "internet", "security", "system",
    "summer", "winter", "spring", "autumn", "iloveyou", "flower"
};
static const int DICTIONARY_WORD_COUNT = sizeof(DICTIONARY_WORDS) / sizeof(DICTIONARY_WORDS[0]);

static const string KEYBOARD_PATTERNS[] = {
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "poiuyt",
    "lkjhgf", "mnbvcx", "1234567890", "0987654321"
};
static const int KEYBOARD_PATTERN_COUNT = sizeof(KEYBOARD_PATTERNS) / sizeof(KEYBOARD_PATTERNS[0]);

static const string COMMON_NAMES[] = {
    "james", "john", "robert", "michael", "david", "william",
    "mary", "patricia", "jennifer", "linda", "elizabeth", "susan",
    "ahmed", "ali", "hassan", "hussain", "usman", "bilal", "faizan",
    "sara", "ayesha", "fatima", "zainab", "hamza", "omar", "khan"
};
static const int COMMON_NAME_COUNT = sizeof(COMMON_NAMES) / sizeof(COMMON_NAMES[0]);

static const string WEAK_SUFFIXES[] = {
    "123", "1234", "12345", "01", "001", "007", "69", "99", "!",
    "!!", "!!!", "2020", "2021", "2022", "2023", "2024", "2025"
};
static const int WEAK_SUFFIX_COUNT = sizeof(WEAK_SUFFIXES) / sizeof(WEAK_SUFFIXES[0]);

static const string WEAK_PREFIXES[] = {
    "admin", "test", "user", "login", "pass", "root", "guest", "welcome"
};
static const int WEAK_PREFIX_COUNT = sizeof(WEAK_PREFIXES) / sizeof(WEAK_PREFIXES[0]);

static string toLowerText(const string& text)
{
    string result = text;
    for (size_t i = 0; i < result.size(); ++i)
    {
        if (result[i] >= 'A' && result[i] <= 'Z')
        {
            result[i] = static_cast<char>(result[i] - 'A' + 'a');
        }
    }
    return result;
}

static bool containsSubstring(const string& text, const string& word)
{
    return text.find(word) != string::npos;
}

// ==============================================================
// INDIVIDUAL PATTERN DETECTION
// ==============================================================

static int countUniqueCharacters(const string& password)
{
    bool seen[256] = { false };
    int uniqueCount = 0;

    for (size_t i = 0; i < password.size(); ++i)
    {
        unsigned char ch = static_cast<unsigned char>(password[i]);
        if (!seen[ch])
        {
            seen[ch] = true;
            uniqueCount++;
        }
    }
    return uniqueCount;
}

static bool checkCommonPassword(const string& lowerPassword)
{
    for (int i = 0; i < COMMON_PASSWORD_COUNT; ++i)
    {
        if (lowerPassword == COMMON_PASSWORDS[i]) return true;
    }
    return false;
}

static bool checkDictionaryWord(const string& lowerPassword)
{
    for (int i = 0; i < DICTIONARY_WORD_COUNT; ++i)
    {
        if (containsSubstring(lowerPassword, DICTIONARY_WORDS[i])) return true;
    }
    return false;
}

static bool checkKeyboardPattern(const string& lowerPassword)
{
    for (int i = 0; i < KEYBOARD_PATTERN_COUNT; ++i)
    {
        if (containsSubstring(lowerPassword, KEYBOARD_PATTERNS[i])) return true;
    }
    return false;
}

static bool checkContainsName(const string& lowerPassword)
{
    for (int i = 0; i < COMMON_NAME_COUNT; ++i)
    {
        if (containsSubstring(lowerPassword, COMMON_NAMES[i])) return true;
    }
    return false;
}

static bool checkWeakSuffix(const string& lowerPassword)
{
    for (int i = 0; i < WEAK_SUFFIX_COUNT; ++i)
    {
        const string& suffix = WEAK_SUFFIXES[i];
        if (lowerPassword.size() >= suffix.size())
        {
            if (lowerPassword.substr(lowerPassword.size() - suffix.size()) == suffix) return true;
        }
    }
    return false;
}

static bool checkWeakPrefix(const string& lowerPassword)
{
    for (int i = 0; i < WEAK_PREFIX_COUNT; ++i)
    {
        const string& prefix = WEAK_PREFIXES[i];
        if (lowerPassword.size() >= prefix.size())
        {
            if (lowerPassword.substr(0, prefix.size()) == prefix) return true;
        }
    }
    return false;
}

static bool checkRepeatedChars(const string& password)
{
    int runLength = 1;
    for (size_t i = 1; i < password.size(); ++i)
    {
        if (password[i] == password[i - 1])
        {
            runLength++;
            if (runLength >= 3) return true;
        }
        else
        {
            runLength = 1;
        }
    }
    return false;
}

static bool checkConsecutiveRepeatedSymbols(const string& password)
{
    const string specialChars = "!@#$%^&*()-_=+[]{};:,.<>?/|~";
    int runLength = 1;

    for (size_t i = 1; i < password.size(); ++i)
    {
        bool isSpecial = specialChars.find(password[i]) != string::npos;
        if (isSpecial && password[i] == password[i - 1])
        {
            runLength++;
            if (runLength >= 3) return true;
        }
        else
        {
            runLength = 1;
        }
    }
    return false;
}

static bool checkRepeatedWords(const string& lowerPassword)
{
    int length = static_cast<int>(lowerPassword.size());
    for (int chunkLength = 3; chunkLength <= length / 2; chunkLength++)
    {
        for (int start = 0; start + (chunkLength * 2) <= length; start++)
        {
            string firstChunk = lowerPassword.substr(start, chunkLength);
            string restOfPassword = lowerPassword.substr(start + chunkLength);
            if (containsSubstring(restOfPassword, firstChunk)) return true;
        }
    }
    return false;
}

static bool checkSequentialLetters(const string& password)
{
    string lower = toLowerText(password);
    for (size_t i = 0; i + 2 < lower.size(); ++i)
    {
        char a = lower[i];
        char b = lower[i + 1];
        char c = lower[i + 2];
        if ((a >= 'a' && a <= 'z') && (b == a + 1) && (c == b + 1)) return true;
    }
    return false;
}

static bool checkSequentialNumbers(const string& password)
{
    for (size_t i = 0; i + 2 < password.size(); ++i)
    {
        char a = password[i];
        char b = password[i + 1];
        char c = password[i + 2];
        if ((a >= '0' && a <= '9') && (b == a + 1) && (c == b + 1)) return true;
    }
    return false;
}

static bool checkAscendingPattern(const string& password)
{
    for (size_t i = 0; i + 2 < password.size(); ++i)
    {
        unsigned char a = static_cast<unsigned char>(password[i]);
        unsigned char b = static_cast<unsigned char>(password[i + 1]);
        unsigned char c = static_cast<unsigned char>(password[i + 2]);
        if (b == a + 1 && c == b + 1) return true;
    }
    return false;
}

static bool checkDescendingPattern(const string& password)
{
    for (size_t i = 0; i + 2 < password.size(); ++i)
    {
        unsigned char a = static_cast<unsigned char>(password[i]);
        unsigned char b = static_cast<unsigned char>(password[i + 1]);
        unsigned char c = static_cast<unsigned char>(password[i + 2]);
        if (b == a - 1 && c == b - 1) return true;
    }
    return false;
}

static bool checkContainsYear(const string& password)
{
    for (size_t i = 0; i + 3 < password.size(); ++i)
    {
        bool allDigits = true;
        for (int j = 0; j < 4; ++j)
        {
            if (password[i + j] < '0' || password[i + j] > '9')
            {
                allDigits = false;
                break;
            }
        }
        if (allDigits)
        {
            int year = (password[i] - '0') * 1000 +
                (password[i + 1] - '0') * 100 +
                (password[i + 2] - '0') * 10 +
                (password[i + 3] - '0');
            if (year >= 1990 && year <= 2035) return true;
        }
    }
    return false;
}

static bool checkContainsEmail(const string& password)
{
    size_t atPos = password.find('@');
    if (atPos == string::npos || atPos == 0) return false;

    size_t dotPos = password.find('.', atPos);
    if (dotPos == string::npos) return false;

    return (dotPos - atPos >= 2) && (password.size() - dotPos >= 3);
}

static int longestDigitRun(const string& password)
{
    int longest = 0;
    int current = 0;

    for (size_t i = 0; i < password.size(); ++i)
    {
        char ch = password[i];
        if (ch >= '0' && ch <= '9')
        {
            current++;
            if (current > longest) longest = current;
        }
        else if (ch != '-' && ch != ' ' && ch != '.')
        {
            current = 0;
        }
    }
    return longest;
}

static bool checkContainsPhonePattern(const string& password)
{
    int digitCount = 0;

    for (size_t i = 0; i < password.size(); ++i)
    {
        char ch = password[i];

        if (ch >= '0' && ch <= '9')
        {
            digitCount++;

            if (digitCount >= 10)
                return true;
        }
        else if (ch == '+' || ch == '-' ||
            ch == ' ' || ch == '(' ||
            ch == ')')
        {
            // Allowed phone-number separators.
        }
        else
        {
            digitCount = 0;
        }
    }

    return false;
}
static bool isValidDate(int day, int month, int year)
{
    if (year < 1900 || year > 2035)
        return false;

    if (month < 1 || month > 12)
        return false;

    int daysInMonth;

    if (month == 2)
    {
        bool leapYear =
            (year % 400 == 0) ||
            (year % 4 == 0 && year % 100 != 0);

        daysInMonth = leapYear ? 29 : 28;
    }
    else if (month == 4 || month == 6 ||
        month == 9 || month == 11)
    {
        daysInMonth = 30;
    }
    else
    {
        daysInMonth = 31;
    }

    return day >= 1 && day <= daysInMonth;
}

static bool checkContainsDobPattern(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        // Check DDMMYYYY
        if (i + 7 < password.size())
        {
            bool allDigits = true;

            for (int j = 0; j < 8; ++j)
            {
                if (password[i + j] < '0' ||
                    password[i + j] > '9')
                {
                    allDigits = false;
                    break;
                }
            }

            if (allDigits)
            {
                int day =
                    (password[i] - '0') * 10 +
                    (password[i + 1] - '0');

                int month =
                    (password[i + 2] - '0') * 10 +
                    (password[i + 3] - '0');

                int year =
                    (password[i + 4] - '0') * 1000 +
                    (password[i + 5] - '0') * 100 +
                    (password[i + 6] - '0') * 10 +
                    (password[i + 7] - '0');

                if (isValidDate(day, month, year))
                    return true;
            }
        }

        // Check DDMMYY
        if (i + 5 < password.size())
        {
            bool allDigits = true;

            for (int j = 0; j < 6; ++j)
            {
                if (password[i + j] < '0' ||
                    password[i + j] > '9')
                {
                    allDigits = false;
                    break;
                }
            }

            if (allDigits)
            {
                int day =
                    (password[i] - '0') * 10 +
                    (password[i + 1] - '0');

                int month =
                    (password[i + 2] - '0') * 10 +
                    (password[i + 3] - '0');

                int shortYear =
                    (password[i + 4] - '0') * 10 +
                    (password[i + 5] - '0');

                int year;

                if (shortYear <= 35)
                    year = 2000 + shortYear;
                else
                    year = 1900 + shortYear;

                if (isValidDate(day, month, year))
                    return true;
            }
        }
    }

    return false;
}

static bool checkContainsSpaces(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (password[i] == ' ') return true;
    }
    return false;
}

static bool checkContainsUnicode(const string& password)
{
    for (size_t i = 0; i < password.size(); ++i)
    {
        if (static_cast<unsigned char>(password[i]) > 127) return true;
    }
    return false;
}

static string undoLeetSubstitutions(const string& password)
{
    string result = password;
    for (size_t i = 0; i < result.size(); ++i)
    {
        switch (result[i])
        {
        case '@': case '4': result[i] = 'a'; break;
        case '0': result[i] = 'o'; break;
        case '1': result[i] = 'i'; break;
        case '3': result[i] = 'e'; break;
        case '5': case '$': result[i] = 's'; break;
        case '7': result[i] = 't'; break;
        default: break;
        }
    }
    return result;
}

static bool checkPredictableSubstitution(const string& lowerPassword, bool alreadyDictionaryWord)
{
    if (alreadyDictionaryWord) return false;
    string unsubstituted = toLowerText(undoLeetSubstitutions(lowerPassword));
    return checkDictionaryWord(unsubstituted) || checkCommonPassword(unsubstituted);
}

// ==============================================================
// MAIN ANALYSIS PIPELINE
// ==============================================================

PasswordAnalysis analyzePassword(const string& password)
{
    PasswordAnalysis analysis;
    analysis.password = password;

    string lowerPassword = toLowerText(password);
    analysis.length = static_cast<int>(password.size());

    for (size_t i = 0; i < password.size(); ++i)
    {
        char ch = password[i];
        if (ch >= 'A' && ch <= 'Z') analysis.upperCount++;
        else if (ch >= 'a' && ch <= 'z') analysis.lowerCount++;
        else if (ch >= '0' && ch <= '9') analysis.digitCount++;
        else if (ch != ' ') analysis.specialCount++;
    }

    analysis.uniqueCount = countUniqueCharacters(password);
    if (analysis.length > 0)
    {
        analysis.diversityPercent = (static_cast<double>(analysis.uniqueCount) / static_cast<double>(analysis.length)) * 100.0;
    }

    analysis.isCommonPassword = checkCommonPassword(lowerPassword);
    analysis.isDictionaryWord = checkDictionaryWord(lowerPassword);
    analysis.hasKeyboardPattern = checkKeyboardPattern(lowerPassword);
    analysis.hasRepeatedChars = checkRepeatedChars(password);
    analysis.hasRepeatedWords = checkRepeatedWords(lowerPassword);
    analysis.hasSequentialLetters = checkSequentialLetters(password);
    analysis.hasSequentialNumbers = checkSequentialNumbers(password);
    analysis.hasAscendingPattern = checkAscendingPattern(password);
    analysis.hasDescendingPattern = checkDescendingPattern(password);
    analysis.containsYear = checkContainsYear(password);
    analysis.containsName = checkContainsName(lowerPassword);
    analysis.containsEmail = checkContainsEmail(password);
    analysis.containsPhonePattern = checkContainsPhonePattern(password);
    analysis.containsDobPattern = checkContainsDobPattern(password);
    analysis.containsSpaces = checkContainsSpaces(password);
    analysis.containsUnicode = checkContainsUnicode(password);
    analysis.hasConsecutiveRepeatedSymbols = checkConsecutiveRepeatedSymbols(password);
    analysis.hasPredictableSubstitution = checkPredictableSubstitution(lowerPassword, analysis.isDictionaryWord);
    // A known common password already has a more serious classification.
    // Skipping affix detection here prevents misleading results such as
    // reporting "password" as a weak-prefix password because it starts with "pass".
    analysis.hasWeakSuffix =
        !analysis.isCommonPassword && checkWeakSuffix(lowerPassword);
    analysis.hasWeakPrefix =
        !analysis.isCommonPassword && checkWeakPrefix(lowerPassword);

    return analysis;
}

// ==============================================================
// SCORING, GRADING AND THREAT EVALUATION
// ==============================================================

int calculateSecurityScore(const PasswordAnalysis& analysis, double entropyBits)
{
    double score = 0.0;

    if (analysis.length >= 8)  score += 8.0;
    if (analysis.length >= 12) score += 6.0;
    if (analysis.length >= 16) score += 6.0;

    score += (analysis.diversityPercent / 100.0) * 15.0;

    if (analysis.upperCount > 0)   score += 5.0;
    if (analysis.lowerCount > 0)   score += 5.0;
    if (analysis.digitCount > 0)   score += 5.0;
    if (analysis.specialCount > 0) score += 5.0;

    double entropyPoints = entropyBits / 3.2;
    if (entropyPoints > 25.0) entropyPoints = 25.0;
    score += entropyPoints;

    if (analysis.isCommonPassword) score -= 40.0;
    if (analysis.isDictionaryWord) score -= 20.0;
    if (analysis.hasPredictableSubstitution) score -= 10.0;
    if (analysis.hasKeyboardPattern) score -= 15.0;
    if (analysis.hasRepeatedChars) score -= 8.0;
    if (analysis.hasRepeatedWords) score -= 8.0;
    if (analysis.hasSequentialLetters) score -= 8.0;
    if (analysis.hasSequentialNumbers) score -= 8.0;
    if (analysis.hasConsecutiveRepeatedSymbols) score -= 5.0;
    if (analysis.containsYear) score -= 5.0;
    if (analysis.containsName) score -= 8.0;
    if (analysis.containsEmail) score -= 10.0;
    if (analysis.containsPhonePattern) score -= 8.0;
    if (analysis.containsDobPattern) score -= 8.0;
    if (analysis.hasWeakSuffix) score -= 5.0;
    if (analysis.hasWeakPrefix) score -= 5.0;
    if (analysis.length < 8) score -= 15.0;

    if (score < 0.0) score = 0.0;
    if (score > 100.0) score = 100.0;

    return static_cast<int>(score + 0.5);
}

string getSecurityGrade(int score)
{
    if (score >= 95) return "A+";
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 55) return "C";
    if (score >= 40) return "D";
    return "F";
}

string getStrengthLabel(int score)
{
    if (score >= 85) return "Very Strong";
    if (score >= 70) return "Strong";
    if (score >= 50) return "Fair";
    if (score >= 30) return "Weak";
    return "Very Weak";
}

string getThreatLevel(int score)
{
    if (score >= 85) return "SAFE";
    if (score >= 70) return "LOW";
    if (score >= 50) return "MEDIUM";
    if (score >= 30) return "HIGH";
    return "CRITICAL";
}

string getThreatLevelColor(const string& threatLevel)
{
    if (threatLevel == "SAFE")     return COLOR_GREEN;
    if (threatLevel == "LOW")      return COLOR_CYAN;
    if (threatLevel == "MEDIUM")   return COLOR_YELLOW;
    return COLOR_RED;
}

// ==============================================================
// INTELLIGENCE ENGINES
// ==============================================================

vector<string> generateExplanations(
    const PasswordAnalysis& analysis,
    double entropyBits
)
{
    vector<string> explanations;

    string positiveMessage;
    string weaknessMessage;
    string conclusionMessage;

    bool hasMixedCharacters =
        analysis.upperCount > 0 &&
        analysis.lowerCount > 0 &&
        analysis.digitCount > 0 &&
        analysis.specialCount > 0;

    bool hasPersonalData =
        analysis.containsName ||
        analysis.containsYear ||
        analysis.containsDobPattern ||
        analysis.containsPhonePattern;

    bool hasPredictablePattern =
        analysis.hasKeyboardPattern ||
        analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers ||
        analysis.hasRepeatedChars ||
        analysis.hasRepeatedWords;

    // A common password should never receive a positive-looking summary.
    // The practical risk is much more important than its theoretical
    // character uniqueness or entropy value.
    if (analysis.isCommonPassword)
    {
        explanations.push_back(
            "Matches an entry in the built-in common-password list."
        );

        explanations.push_back(
            "A common dictionary word is highly vulnerable to automated guessing."
        );

        explanations.push_back(
            "Replace this password completely instead of modifying it."
        );

        return explanations;
    }

    // ============================================================
    // POSITIVE OBSERVATION
    // ============================================================
    if (entropyBits >= 60.0 &&
        hasMixedCharacters &&
        analysis.diversityPercent >= 70.0)
    {
        positiveMessage =
            "Strong entropy, character variety, and uniqueness detected.";
    }
    else if (hasMixedCharacters)
    {
        positiveMessage =
            "Good character variety using uppercase, lowercase, numbers, and symbols.";
    }
    else if (analysis.diversityPercent >= 70.0)
    {
        positiveMessage =
            "High character uniqueness reduces repeated-character weakness.";
    }

    // ============================================================
    // MOST IMPORTANT WEAKNESS
    // ============================================================
    if (analysis.isCommonPassword)
    {
        weaknessMessage =
            "Matches an entry in the built-in common-password list.";
    }
    else if (analysis.isDictionaryWord)
    {
        weaknessMessage =
            "Contains a dictionary word targeted by automated attacks.";
    }
    else if (analysis.hasPredictableSubstitution)
    {
        weaknessMessage =
            "Uses predictable character substitutions recognized by password crackers.";
    }
    else if (hasPersonalData)
    {
        weaknessMessage =
            "Contains personal information that may enable targeted guessing.";
    }
    else if (analysis.hasKeyboardPattern)
    {
        weaknessMessage =
            "Contains a keyboard pattern commonly tested during password attacks.";
    }
    else if (analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers)
    {
        weaknessMessage =
            "Contains predictable sequential characters.";
    }
    else if (analysis.hasRepeatedChars ||
        analysis.hasRepeatedWords)
    {
        weaknessMessage =
            "Contains repeated characters or repeated text patterns.";
    }
    else if (analysis.length < 12)
    {
        weaknessMessage =
            "Password length is below the recommended 12-character minimum.";
    }
    else if (entropyBits < 36.0)
    {
        weaknessMessage =
            "Low entropy indicates limited unpredictability.";
    }
    else
    {
        weaknessMessage =
            "No common-password or obvious predictable pattern was detected.";
    }

    // ============================================================
    // OVERALL SECURITY CONCLUSION
    // ============================================================
    if (analysis.isCommonPassword ||
        analysis.isDictionaryWord ||
        analysis.hasPredictableSubstitution)
    {
        conclusionMessage =
            "Vulnerable to dictionary and hybrid password attacks.";
    }
    else if (hasPersonalData)
    {
        conclusionMessage =
            "Brute-force resistance may be high, but targeted guessing remains a risk.";
    }
    else if (hasPredictablePattern)
    {
        conclusionMessage =
            "Predictable patterns reduce security despite the calculated entropy.";
    }
    else if (analysis.length < 12)
    {
        conclusionMessage =
            "Increasing the length would significantly improve overall resistance.";
    }
    else if (entropyBits >= 60.0 &&
        hasMixedCharacters &&
        analysis.diversityPercent >= 70.0)
    {
        conclusionMessage =
            "No major weaknesses were found by the local password analysis.";
    }
    else
    {
        conclusionMessage =
            "Additional length and character variety would improve security.";
    }

    // Add a maximum of three useful summary lines.
    if (!positiveMessage.empty())
    {
        explanations.push_back(positiveMessage);
    }

    if (!weaknessMessage.empty())
    {
        explanations.push_back(weaknessMessage);
    }

    if (!conclusionMessage.empty())
    {
        explanations.push_back(conclusionMessage);
    }

    return explanations;
}

vector<string> generateRecommendations(const PasswordAnalysis& analysis)
{
    vector<string> recommendations;

    auto addRecommendation =
        [&recommendations](const string& message)
        {
            if (recommendations.size() < 6)
            {
                recommendations.push_back(message);
            }
        };

    // Special handling for commonly used passwords.
    if (analysis.isCommonPassword)
    {
        addRecommendation(
            "Replace this commonly used password immediately"
        );

        addRecommendation(
            "Avoid using a single dictionary word as your password"
        );

        if (analysis.length < 12)
        {
            addRecommendation(
                "Increase password length to at least 12 characters"
            );
        }

        addRecommendation(
            "Use unrelated random words or a randomly generated password"
        );

        return recommendations;
    }

    if (analysis.isDictionaryWord)
    {
        addRecommendation(
            "Replace dictionary words with random combinations"
        );
    }

    if (analysis.containsName ||
        analysis.containsYear ||
        analysis.containsDobPattern ||
        analysis.containsPhonePattern ||
        analysis.containsEmail)
    {
        addRecommendation(
            "Remove personal identifiers such as names, dates, or phone numbers"
        );
    }

    if (analysis.hasKeyboardPattern ||
        analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers)
    {
        addRecommendation(
            "Remove keyboard patterns and sequential characters"
        );
    }

    if (analysis.hasRepeatedChars ||
        analysis.hasRepeatedWords)
    {
        addRecommendation(
            "Replace repeated characters or repeated text patterns"
        );
    }

    if (analysis.hasPredictableSubstitution)
    {
        addRecommendation(
            "Avoid predictable substitutions such as @ for A or 0 for O"
        );
    }

    if (analysis.hasWeakPrefix ||
        analysis.hasWeakSuffix)
    {
        addRecommendation(
            "Remove predictable prefixes, suffixes, or number endings"
        );
    }

    if (analysis.length < 12)
    {
        addRecommendation(
            "Increase password length to at least 12 characters"
        );
    }

    if (analysis.upperCount == 0)
    {
        addRecommendation(
            "Add at least one uppercase letter"
        );
    }

    if (analysis.lowerCount == 0)
    {
        addRecommendation(
            "Add at least one lowercase letter"
        );
    }

    if (analysis.digitCount == 0)
    {
        addRecommendation(
            "Add at least one number"
        );
    }

    if (analysis.specialCount == 0)
    {
        addRecommendation(
            "Add at least one special symbol"
        );
    }

    if (recommendations.empty())
    {
        addRecommendation(
            "No immediate password-specific improvements are required"
        );
    }

    return recommendations;
}

// ==============================================================
// DASHBOARD FORMATTING HELPERS
// ==============================================================

static string buildProgressBar(int current, int max, int barWidth = 30)
{
    string bar;
    int filled = (current * barWidth) / max;

    bar = "[";
    for (int i = 0; i < barWidth; i++)
    {
        if (i < filled) bar += "=";
        else if (i == filled) bar += ">";
        else bar += " ";
    }
    bar += "]";

    return bar;
}

static string formatStatus(bool condition, const string& okText = "OK", const string& failText = "MISSING")
{
    if (condition)
        return COLOR_GREEN + "[" + okText + "]" + COLOR_RESET;
    else
        return COLOR_RED + "[" + failText + "]" + COLOR_RESET;
}

static string formatThreatTag(const string& rawTime)
{
    if (rawTime.find("Instant") != string::npos ||
        rawTime.find("Seconds") != string::npos ||
        rawTime.find("seconds") != string::npos ||
        rawTime.find("Minutes") != string::npos ||
        rawTime.find("minutes") != string::npos)
    {
        return COLOR_RED + rawTime + COLOR_RESET;
    }

    if (rawTime.find("Hours") != string::npos ||
        rawTime.find("hours") != string::npos ||
        rawTime.find("Days") != string::npos ||
        rawTime.find("days") != string::npos)
    {
        return COLOR_YELLOW + rawTime + COLOR_RESET;
    }

    if (rawTime.find("years") != string::npos ||
        rawTime.find("Years") != string::npos)
    {
        return COLOR_GREEN + rawTime + COLOR_RESET;
    }

    return COLOR_CYAN + rawTime + COLOR_RESET;
}

static string getDetectedPatternsBadge(const PasswordAnalysis& analysis)
{
    vector<string> patterns;

    if (analysis.hasKeyboardPattern)
    {
        patterns.push_back("KEYBOARD");
    }

    if (analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers)
    {
        patterns.push_back("SEQUENTIAL");
    }

    if (analysis.hasRepeatedChars ||
        analysis.hasRepeatedWords)
    {
        patterns.push_back("REPEATED");
    }

    if (analysis.containsName)
    {
        patterns.push_back("NAME");
    }

    if (analysis.containsYear)
    {
        patterns.push_back("YEAR");
    }

    if (analysis.containsEmail)
    {
        patterns.push_back("EMAIL");
    }

    if (analysis.containsPhonePattern)
    {
        patterns.push_back("PHONE");
    }

    if (analysis.containsDobPattern)
    {
        patterns.push_back("DOB");
    }

    if (analysis.hasPredictableSubstitution)
    {
        patterns.push_back("LEET");
    }

    if (analysis.hasWeakPrefix ||
        analysis.hasWeakSuffix)
    {
        patterns.push_back("WEAK AFFIX");
    }

    if (patterns.empty())
    {
        return COLOR_GREEN + "[NONE]" + COLOR_RESET;
    }

    string result = COLOR_RED;

    for (size_t i = 0; i < patterns.size(); ++i)
    {
        result += "[" + patterns[i] + "]";

        if (i + 1 < patterns.size())
        {
            result += " ";
        }
    }

    result += COLOR_RESET;

    return result;
}

static string getDetectedPatternsText(
    const PasswordAnalysis& analysis
)
{
    vector<string> patterns;

    if (analysis.hasKeyboardPattern) patterns.push_back("KEYBOARD");

    if (analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers)
    {
        patterns.push_back("SEQUENTIAL");
    }

    if (analysis.hasRepeatedChars ||
        analysis.hasRepeatedWords)
    {
        patterns.push_back("REPEATED");
    }

    if (analysis.containsName) patterns.push_back("NAME");
    if (analysis.containsYear) patterns.push_back("YEAR");
    if (analysis.containsEmail) patterns.push_back("EMAIL");
    if (analysis.containsPhonePattern) patterns.push_back("PHONE");
    if (analysis.containsDobPattern) patterns.push_back("DOB");

    if (analysis.hasPredictableSubstitution)
    {
        patterns.push_back("LEET");
    }

    if (analysis.hasWeakPrefix ||
        analysis.hasWeakSuffix)
    {
        patterns.push_back("WEAK AFFIX");
    }

    if (patterns.empty())
    {
        return "[NONE]";
    }

    string result;

    for (size_t i = 0; i < patterns.size(); ++i)
    {
        result += "[" + patterns[i] + "]";

        if (i + 1 < patterns.size())
        {
            result += " ";
        }
    }

    return result;
}

static void printCompactRow(
    const string& label,
    const string& value,
    int labelWidth = 28
)
{
    cout << "  "
        << left << setw(labelWidth) << label
        << " "
        << value
        << "\n";
}

static void printSectionHeader(const string& title)
{
    cout << "\n"
        << COLOR_CYAN
        << "  [" << title << "]"
        << COLOR_RESET
        << "\n";

    cout << "  " << string(45, '-') << "\n";
}

static void printAnalyzerRow(
    const string& label,
    const string& value,
    int labelWidth = 22
)
{
    cout << "  "
        << left << setw(labelWidth) << label
        << " : "
        << value
        << "\n";
}

// ==============================================================
// HIGH-IMPACT TERMINAL DASHBOARD
// ==============================================================
static string centerText(const string& text, int width)
{
    if (static_cast<int>(text.length()) >= width)
    {
        return text.substr(0, width);
    }

    int totalSpaces = width - static_cast<int>(text.length());
    int leftSpaces = totalSpaces / 2;
    int rightSpaces = totalSpaces - leftSpaces;

    return string(leftSpaces, ' ') +
        text +
        string(rightSpaces, ' ');
}

// Prints a standard border used by all analyzer boxes.
static void printDashboardBorder(int width)
{
    cout << "  "
        << COLOR_WHITE
        << "+"
        << string(width, '-')
        << "+"
        << COLOR_RESET
        << "\n";
}

// Prints an empty row inside a dashboard box.
static void printDashboardEmptyRow(int width)
{
    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << string(width, ' ')
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a centered title between two borders.
static void printDashboardBoxTitle(
    const string& title,
    int width
)
{
    printDashboardBorder(width);

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << COLOR_CYAN
        << centerText("-- " + title + " --", width)
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";

    printDashboardBorder(width);
}

// Prints a plain row and keeps the right border aligned.
static void printDashboardTextRow(
    const string& text,
    int width
)
{
    const int contentWidth = width - 4;
    string displayText = text;

    if (static_cast<int>(displayText.length()) > contentWidth)
    {
        displayText = displayText.substr(0, contentWidth);
    }

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "  "
        << left
        << setw(contentWidth)
        << displayText
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a label and a colored value.
// Long values automatically continue on another row.
static void printDashboardValueRow(
    const string& label,
    const string& value,
    const string& valueColor,
    int width,
    int labelWidth = 14
)
{
    const int contentWidth = width - 4;
    const string separator = " : ";

    string shownLabel = label;

    if (static_cast<int>(shownLabel.length()) > labelWidth)
    {
        shownLabel = shownLabel.substr(0, labelWidth);
    }

    int valueWidth =
        contentWidth -
        labelWidth -
        static_cast<int>(separator.length());

    if (valueWidth <= 0)
    {
        printDashboardTextRow(label, width);
        return;
    }

    size_t position = 0;
    bool firstLine = true;

    do
    {
        string part = value.substr(position, valueWidth);

        cout << "  "
            << COLOR_WHITE
            << "|"
            << COLOR_RESET
            << "  ";

        if (firstLine)
        {
            cout << left
                << setw(labelWidth)
                << shownLabel
                << separator;
        }
        else
        {
            cout << string(labelWidth, ' ')
                << string(separator.length(), ' ');
        }

        cout << valueColor
            << left
            << setw(valueWidth)
            << part
            << COLOR_RESET
            << "  "
            << COLOR_WHITE
            << "|"
            << COLOR_RESET
            << "\n";

        position += part.length();
        firstLine = false;

    } while (position < value.length());
}


// Prints two label/value pairs on the same row.
// This keeps Overview and Character Composition aligned
// automatically when the main box width changes.
static void printDashboardDoubleRow(
    const string& leftLabel,
    const string& leftValue,
    const string& leftColor,
    const string& rightLabel,
    const string& rightValue,
    const string& rightColor,
    int width
)
{
    const int contentWidth = width - 4;
    const int leftColumnWidth = contentWidth / 2;
    const int rightColumnWidth = contentWidth - leftColumnWidth;

    string leftText = leftLabel + " : " + leftValue;
    string rightText = rightLabel + " : " + rightValue;

    if (static_cast<int>(leftText.length()) > leftColumnWidth)
    {
        leftText = leftText.substr(0, leftColumnWidth);
    }

    if (static_cast<int>(rightText.length()) > rightColumnWidth)
    {
        rightText = rightText.substr(0, rightColumnWidth);
    }

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "  "
        << leftColor
        << left
        << setw(leftColumnWidth)
        << leftText
        << COLOR_RESET
        << rightColor
        << left
        << setw(rightColumnWidth)
        << rightText
        << COLOR_RESET
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Selects a color for crack-time text without changing its logic.
static string getCrackTimeColor(const string& rawTime)
{
    if (rawTime.find("Instant") != string::npos ||
        rawTime.find("Seconds") != string::npos ||
        rawTime.find("seconds") != string::npos ||
        rawTime.find("Minutes") != string::npos ||
        rawTime.find("minutes") != string::npos)
    {
        return COLOR_RED;
    }

    if (rawTime.find("Hours") != string::npos ||
        rawTime.find("hours") != string::npos ||
        rawTime.find("Days") != string::npos ||
        rawTime.find("days") != string::npos)
    {
        return COLOR_YELLOW;
    }

    if (rawTime.find("Years") != string::npos ||
        rawTime.find("years") != string::npos)
    {
        return COLOR_GREEN;
    }

    return COLOR_CYAN;
}

void printPasswordDashboard(const PasswordAnalysis& analysis)
{
    EntropyResult entropy =
        calculateEntropyDetails(analysis.password);

    int score =
        calculateSecurityScore(analysis, entropy.entropyBits);

    string grade = getSecurityGrade(score);
    string threatLevel = getThreatLevel(score);
    string threatColor = getThreatLevelColor(threatLevel);
    string strength = getStrengthLabel(score);
    string scoreColor = getScoreColor(score);

    const int boxWidth = 54;

    // Clear the screen before printing the dashboard.
    cout << "\033[2J\033[1;1H";

    // ============================================================
    // TOP DASHBOARD HEADER
    // ============================================================

    cout << "\n";
    printDashboardBorder(boxWidth);

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << COLOR_CYAN
        << centerText(
            "-- PASSWORD SECURITY DASHBOARD --",
            boxWidth
        )
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << COLOR_YELLOW
        << centerText(
            "Live Risk & Strength Analysis",
            boxWidth
        )
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";

    printDashboardBorder(boxWidth);

    // ============================================================
    // OVERVIEW
    // ============================================================

    cout << "\n";
    printDashboardBoxTitle("OVERVIEW", boxWidth);
    printDashboardEmptyRow(boxWidth);

    printDashboardDoubleRow(
        "SCORE",
        to_string(score) + " / 100",
        scoreColor,
        "THREAT",
        "[" + threatLevel + "]",
        threatColor,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardDoubleRow(
        "STRENGTH",
        strength,
        scoreColor,
        "GRADE",
        grade,
        scoreColor,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "LENGTH",
        to_string(analysis.length) + " Characters",
        COLOR_RESET,
        boxWidth,
        10
    );

    printDashboardEmptyRow(boxWidth);
    printDashboardBorder(boxWidth);

    // ============================================================
    // CHARACTER COMPOSITION
    // ============================================================

    string diversityLevel;
    string diversityColor;

    if (analysis.diversityPercent >= 75.0)
    {
        diversityLevel = "[HIGH]";
        diversityColor = COLOR_GREEN;
    }
    else if (analysis.diversityPercent >= 50.0)
    {
        diversityLevel = "[MEDIUM]";
        diversityColor = COLOR_YELLOW;
    }
    else
    {
        diversityLevel = "[LOW]";
        diversityColor = COLOR_RED;
    }

    cout << "\n";
    printDashboardBoxTitle(
        "CHARACTER COMPOSITION",
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardDoubleRow(
        "UPPERCASE",
        to_string(analysis.upperCount),
        COLOR_RESET,
        "LOWERCASE",
        to_string(analysis.lowerCount),
        COLOR_RESET,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardDoubleRow(
        "NUMBERS",
        to_string(analysis.digitCount),
        COLOR_RESET,
        "SYMBOLS",
        to_string(analysis.specialCount),
        COLOR_RESET,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardDoubleRow(
        "UNIQUE",
        to_string(analysis.uniqueCount) +
        " / " +
        to_string(analysis.length),
        COLOR_RESET,
        "UNIQUENESS",
        to_string(
            static_cast<int>(analysis.diversityPercent)
        ) +
        "% " +
        diversityLevel,
        diversityColor,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);
    printDashboardBorder(boxWidth);

    // ============================================================
    // ENTROPY & PATTERN SCAN
    // ============================================================

    string practicalStatus;
    string practicalReason;
    string practicalColor;

    if (analysis.isCommonPassword)
    {
        practicalStatus = "[SEVERELY REDUCED]";
        practicalReason = "Common password match";
        practicalColor = COLOR_RED;
    }
    else if (analysis.isDictionaryWord)
    {
        practicalStatus = "[REDUCED]";
        practicalReason = "Dictionary word detected";
        practicalColor = COLOR_RED;
    }
    else if (
        analysis.hasPredictableSubstitution ||
        analysis.hasKeyboardPattern ||
        analysis.hasSequentialLetters ||
        analysis.hasSequentialNumbers
        )
    {
        practicalStatus = "[REDUCED]";
        practicalReason = "Predictable pattern detected";
        practicalColor = COLOR_YELLOW;
    }
    else
    {
        practicalStatus = "[NO MAJOR REDUCTION]";
        practicalReason = "No predictable patterns detected";
        practicalColor = COLOR_GREEN;
    }

    cout << "\n";
    printDashboardBoxTitle(
        "ENTROPY & PATTERN SCAN",
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "THEORETICAL",
        to_string(
            static_cast<int>(entropy.entropyBits)
        ) +
        " bits [" +
        entropy.complexityLabel +
        "]",
        COLOR_CYAN,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "PRACTICAL",
        practicalStatus,
        practicalColor,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "REASON",
        practicalReason,
        practicalColor,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "SEARCH SPACE",
        entropy.searchSpaceText,
        COLOR_CYAN,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "DICTIONARY",
        analysis.isDictionaryWord
        ? "[DETECTED]"
        : "[CLEAR]",
        analysis.isDictionaryWord
        ? COLOR_RED
        : COLOR_GREEN,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "COMMON MATCH",
        analysis.isCommonPassword
        ? "[DETECTED]"
        : "[NOT FOUND]",
        analysis.isCommonPassword
        ? COLOR_RED
        : COLOR_GREEN,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    string patternText = getDetectedPatternsText(analysis);

    printDashboardValueRow(
        "PATTERNS",
        patternText,
        patternText == "[NONE]"
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth
    );

    if (!analysis.isCommonPassword)
    {
        printDashboardEmptyRow(boxWidth);

        printDashboardValueRow(
            "BREACH CHECK",
            "Use Live Breach Checker",
            COLOR_YELLOW,
            boxWidth
        );
    }

    printDashboardEmptyRow(boxWidth);
    printDashboardBorder(boxWidth);

    // ============================================================
    // ESTIMATED CRACK TIME
    // ============================================================

    CrackTimeEstimates crackTimes =
        estimateCrackTimes(
            entropy.entropyBits,
            analysis.isDictionaryWord,
            analysis.isCommonPassword
        );

    string effectiveCrackTime;
    string primaryRisk;

    if (analysis.isCommonPassword)
    {
        effectiveCrackTime =
            crackTimes.dictionaryAttack;

        primaryRisk =
            "Common password match";
    }
    else if (analysis.isDictionaryWord)
    {
        effectiveCrackTime =
            crackTimes.dictionaryAttack;

        primaryRisk =
            "Dictionary word detected";
    }
    else if (analysis.hasPredictableSubstitution)
    {
        effectiveCrackTime =
            crackTimes.hybridAttack;

        primaryRisk =
            "Predictable substitution detected";
    }
    else
    {
        effectiveCrackTime =
            crackTimes.bruteForceAttack;

        primaryRisk =
            "No faster attack detected";
    }

    cout << "\n";
    printDashboardBoxTitle(
        "ESTIMATED CRACK TIME",
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "EFFECTIVE",
        effectiveCrackTime,
        getCrackTimeColor(effectiveCrackTime),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "PRIMARY RISK",
        primaryRisk,
        COLOR_YELLOW,
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "DICTIONARY",
        crackTimes.dictionaryAttack,
        getCrackTimeColor(
            crackTimes.dictionaryAttack
        ),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "HYBRID",
        crackTimes.hybridAttack,
        getCrackTimeColor(
            crackTimes.hybridAttack
        ),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "OFFLINE GPU",
        crackTimes.gpuAttack,
        getCrackTimeColor(
            crackTimes.gpuAttack
        ),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "BRUTE FORCE",
        crackTimes.bruteForceAttack,
        getCrackTimeColor(
            crackTimes.bruteForceAttack
        ),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "ONLINE LIMIT",
        crackTimes.onlineAttack,
        getCrackTimeColor(
            crackTimes.onlineAttack
        ),
        boxWidth
    );

    printDashboardEmptyRow(boxWidth);
    printDashboardBorder(boxWidth);

    // ============================================================
    // INTELLIGENCE SUMMARY
    // ============================================================

    printSectionHeader("INTELLIGENCE SUMMARY");

    vector<string> explanations =
        generateExplanations(
            analysis,
            entropy.entropyBits
        );

    for (
        size_t i = 0;
        i < explanations.size() && i < 3;
        ++i
        )
    {
        cout << "  - "
            << explanations[i]
            << "\n";
    }

    // ============================================================
    // RECOMMENDATIONS
    // ============================================================

    printSectionHeader("RECOMMENDATIONS");

    vector<string> recommendations =
        generateRecommendations(analysis);

    for (
        size_t i = 0;
        i < recommendations.size() && i < 6;
        ++i
        )
    {
        cout << "  "
            << COLOR_YELLOW
            << "P" << (i + 1)
            << COLOR_RESET
            << "  "
            << recommendations[i]
            << "\n";
    }

    // ============================================================
    // SECURITY CHECKLIST
    // ============================================================

    cout << "\n";
    printDashboardBoxTitle(
        "SECURITY CHECKLIST",
        boxWidth);

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "LENGTH >= 12",
        analysis.length >= 12
        ? "[PASS]"
        : "[FAIL]",
        analysis.length >= 12
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    bool mixedCase =
        analysis.upperCount > 0 &&
        analysis.lowerCount > 0;

    printDashboardValueRow(
        "MIXED CASE",
        mixedCase ? "[PASS]" : "[FAIL]",
        mixedCase ? COLOR_GREEN : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    bool numbersAndSymbols =
        analysis.digitCount > 0 &&
        analysis.specialCount > 0;

    printDashboardValueRow(
        "NUMBERS + SYMBOLS",
        numbersAndSymbols
        ? "[PASS]"
        : "[FAIL]",
        numbersAndSymbols
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "NO DICTIONARY MATCH",
        !analysis.isDictionaryWord
        ? "[PASS]"
        : "[FAIL]",
        !analysis.isDictionaryWord
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "NO COMMON MATCH",
        !analysis.isCommonPassword
        ? "[PASS]"
        : "[FAIL]",
        !analysis.isCommonPassword
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    printDashboardValueRow(
        "NO KEYBOARD PATTERN",
        !analysis.hasKeyboardPattern
        ? "[PASS]"
        : "[FAIL]",
        !analysis.hasKeyboardPattern
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    bool noSequences =
        !analysis.hasSequentialLetters &&
        !analysis.hasSequentialNumbers;

    printDashboardValueRow(
        "NO SEQUENCES",
        noSequences ? "[PASS]" : "[FAIL]",
        noSequences ? COLOR_GREEN : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);

    bool noPersonalData =
        !analysis.containsName &&
        !analysis.containsYear &&
        !analysis.containsDobPattern &&
        !analysis.containsPhonePattern &&
        !analysis.containsEmail;

    printDashboardValueRow(
        "NO PERSONAL DATA",
        noPersonalData
        ? "[PASS]"
        : "[FAIL]",
        noPersonalData
        ? COLOR_GREEN
        : COLOR_RED,
        boxWidth,
        22
    );

    printDashboardEmptyRow(boxWidth);
    printDashboardBorder(boxWidth);

    // ============================================================
    // FOOTER
    // ============================================================

    cout << "\n";
    printDashboardBorder(boxWidth);

    cout << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << COLOR_GREEN
        << centerText(
            "Scan Completed - Password Guardian",
            boxWidth
        )
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";

    printDashboardBorder(boxWidth);
}