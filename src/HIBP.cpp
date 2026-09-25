/*
    ============================================================
    HIBP.CPP
    ============================================================
    See HIBP.h for an overview. Section 1 (SHA-1) is copied over
    from the original Password Guardian project without any
    changes to the actual algorithm - it still works exactly the
    same way. Section 2 (the breach check) keeps the same
    k-Anonymity logic, with a more detailed report printed at
    the end.
    ============================================================
*/

#include "HIBP.h"
#include "Utils.h"
#include <iostream>
#include <cstdio>
#include <sstream>
#include <string>
#include <iomanip>   // setw, left, right
#include <windows.h> // Sleep

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

using namespace std;

/*
    ============================================================
    SECTION 1: SHA-1 IMPLEMENTATION (PURE C++, UNCHANGED LOGIC)
    ============================================================
    The Have I Been Pwned API needs a SHA-1 hash of the
    password before it can check it against breach data.
    This is a simple, from-scratch SHA-1 implementation.
    No external libraries are used.
    ============================================================
*/

// Left-rotate a 32-bit number by "bits" positions.
// SHA-1 uses this operation many times during hashing.
unsigned int leftRotate(unsigned int value, unsigned int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

// Takes a normal text password and returns its SHA-1 hash
// as an uppercase hex string (this is what the HIBP API wants).
string sha1Hash(const string& input)
{
    // Initial hash values (fixed constants defined by the SHA-1 standard)
    unsigned int h0 = 0x67452301;
    unsigned int h1 = 0xEFCDAB89;
    unsigned int h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476;
    unsigned int h4 = 0xC3D2E1F0;

    // ---- Step 1: Pre-processing (padding the message) ----
    string message = input;
    unsigned long long originalBitLength = (unsigned long long)message.size() * 8;

    // Append a single '1' bit (as byte 0x80)
    message += (char)0x80;

    // Pad with '0' bits until length in bytes is congruent to 56 mod 64
    while (message.size() % 64 != 56)
    {
        message += (char)0x00;
    }

    // Append original length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; i--)
    {
        char byte = (char)((originalBitLength >> (i * 8)) & 0xFF);
        message += byte;
    }

    // ---- Step 2: Process the message in 512-bit (64-byte) chunks ----
    for (size_t chunkStart = 0; chunkStart < message.size(); chunkStart += 64)
    {
        unsigned int w[80];

        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; i++)
        {
            int base = (int)chunkStart + i * 4;
            w[i] = ((unsigned char)message[base] << 24) |
                ((unsigned char)message[base + 1] << 16) |
                ((unsigned char)message[base + 2] << 8) |
                ((unsigned char)message[base + 3]);
        }

        // Extend the sixteen words into eighty words
        for (int i = 16; i < 80; i++)
        {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        // Initialize working variables for this chunk
        unsigned int a = h0;
        unsigned int b = h1;
        unsigned int c = h2;
        unsigned int d = h3;
        unsigned int e = h4;

        // Main SHA-1 compression loop (80 rounds)
        for (int i = 0; i < 80; i++)
        {
            unsigned int f, k;

            if (i < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            unsigned int temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's result into the running hash values
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // ---- Step 3: Combine the five hash values into one hex string ----
    char result[41];
    sprintf_s(result, sizeof(result), "%08X%08X%08X%08X%08X",
        h0, h1, h2, h3, h4);

    return string(result);
}

/*
    ============================================================
    SECTION 2: HAVE I BEEN PWNED BREACH CHECK (k-ANONYMITY)
    ============================================================
    Steps:
      1. Hash the password using SHA-1
      2. Take the first 5 characters of the hash (the "prefix")
      3. Send only the prefix to the API using curl
      4. The API returns a list of hash suffixes that share
         that prefix, along with how many times each has
         appeared in known data breaches
      5. Search locally for our password's suffix in that list
      This way, the full password hash is NEVER sent over
      the internet - only the first 5 characters are shared.
    ============================================================
*/

// Runs a system command and returns its console output as a string.
// This is how we call "curl" and capture what it prints.
string runSystemCommand(const string& command)
{
    string result = "";
    char buffer[256];

    // popen runs the command and lets us read its output like a file
    FILE* pipe = popen(command.c_str(), "r");

    if (!pipe)
    {
        return "ERROR";
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        result += buffer;
    }

    pclose(pipe);
    return result;
}

// Sends only the hash prefix to the API and checks the response
// locally for our password's hash suffix.
BreachCheckResult checkPasswordAgainstHIBP(const string& password)
{
    BreachCheckResult breachResult;

    // Convert password to SHA-1 hash
    string fullHash = sha1Hash(password);

    // Split hash into prefix (sent to the API) and suffix (kept local)
    breachResult.hashPrefix = fullHash.substr(0, 5);
    breachResult.hashSuffix = fullHash.substr(5);

    // Build API URL and command
    string url = "https://api.pwnedpasswords.com/range/" + breachResult.hashPrefix;
    string command = "curl -s \"" + url + "\"";

    // Get API response
    string response = runSystemCommand(command);

    if (response.empty() || response == "ERROR")
    {
        breachResult.connectedSuccessfully = false;
        return breachResult;
    }

    breachResult.connectedSuccessfully = true;

    // Read response line by line, looking for our suffix
    stringstream ss(response);
    string line;

    while (getline(ss, line))
    {
        // Remove '\r' if present
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        size_t colon = line.find(':');

        if (colon != string::npos)
        {
            string apiSuffix = line.substr(0, colon);
            string count = line.substr(colon + 1);

            if (apiSuffix == breachResult.hashSuffix)
            {
                breachResult.foundInBreach = true;
                breachResult.occurrences = stoi(count);
                break;
            }
        }
    }

    return breachResult;
}
static void showHIBPSpinner(const string& label)
{
    const char spinner[] = { '|', '/', '-', '\\' };

    cout << "  |  "
        << left
        << setw(35)
        << label
        << spinner[0];

    for (int i = 1; i < 20; i++)
    {
        cout << "\b"
            << COLOR_CYAN
            << spinner[i % 4]
            << COLOR_RESET;

        cout.flush();
        Sleep(80);
    }

    cout << "\b"
        << COLOR_GREEN
        << "[OK]"
        << COLOR_RESET
        << string(9, ' ')
        << "|\n";
}

static string centerText(const string& text, int width)
{
    if (static_cast<int>(text.length()) >= width)
    {
        return text.substr(0, width);
    }

    int totalSpaces = width - static_cast<int>(text.length());
    int leftSpaces = totalSpaces / 2;
    int rightSpaces = totalSpaces - leftSpaces;

    return string(leftSpaces, ' ')
        + text
        + string(rightSpaces, ' ');
}

static string formatNumber(long long number)
{
    string value = to_string(number);

    for (int i = static_cast<int>(value.length()) - 3; i > 0; i -= 3)
    {
        value.insert(i, ",");
    }

    return value;
}

// Converts large values into readable units while preserving the exact number.
// Example: 52,372,427 becomes "52.37 million (52,372,427)".
static string formatReadableCount(long long number)
{
    double value = static_cast<double>(number);
    string unit = "";

    if (number >= 1000000000000LL)
    {
        value = value / 1000000000000.0;
        unit = "trillion";
    }
    else if (number >= 1000000000LL)
    {
        value = value / 1000000000.0;
        unit = "billion";
    }
    else if (number >= 1000000LL)
    {
        value = value / 1000000.0;
        unit = "million";
    }
    else if (number >= 1000LL)
    {
        value = value / 1000.0;
        unit = "thousand";
    }
    else
    {
        return formatNumber(number);
    }

    stringstream output;
    output << fixed << setprecision(2) << value;

    string readable = output.str();

    // Remove unnecessary trailing zeros.
    while (!readable.empty() && readable.back() == '0')
    {
        readable.pop_back();
    }

    if (!readable.empty() && readable.back() == '.')
    {
        readable.pop_back();
    }

    return readable + " " + unit + " (" + formatNumber(number) + ")";
}

static void printBoxBorder(int width)
{
    cout << "  "
        << COLOR_WHITE
        << "+"
        << string(width, '-')
        << "+"
        << COLOR_RESET
        << "\n";
}

static void printBoxTitle(const string& title, int width)
{
    printBoxBorder(width);

    cout << "  "
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << COLOR_CYAN
        << centerText("-- " + title + " --", width)
        << COLOR_RESET
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";

    printBoxBorder(width);
}

static void printEmptyBoxRow(int width)
{
    cout << "  |"
        << string(width, ' ')
        << "|\n";
}

static void printBoxTextRow(const string& text, int width)
{
    string safeText = text;
    int availableWidth = width - 2;

    if (static_cast<int>(safeText.length()) > availableWidth)
    {
        safeText = safeText.substr(0, availableWidth);
    }

    cout << "  |  "
        << left
        << setw(availableWidth)
        << safeText
        << "|\n";
}

static void printColoredBoxRow(
    const string& label,
    const string& value,
    const string& color,
    int width
)
{
    string plainText = label + value;
    int trailingSpaces = width - 2 - static_cast<int>(plainText.length());

    if (trailingSpaces < 0)
    {
        trailingSpaces = 0;
    }

    cout << "  |  "
        << label
        << color
        << value
        << COLOR_RESET
        << string(trailingSpaces, ' ')
        << "|\n";
}

// Prints the full, upgraded breach report shown from the main menu.
void checkBreachDatabase()
{
    string password;

    cout << "\nEnter password to check: ";
    cin >> password;

    const int boxWidth = 50;

    // ============================================================
    // TOP BREACH REPORT HEADER
    // ============================================================

    cout << "\n";

    printBoxBorder(boxWidth);

    cout << "  "
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << COLOR_CYAN
        << centerText("-- ONLINE BREACH REPORT --", boxWidth)
        << COLOR_RESET
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";

    cout << "  "
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << centerText("Have I Been Pwned Security Check", boxWidth)
        << COLOR_WHITE << "|"
        << COLOR_RESET
        << "\n";

    printBoxBorder(boxWidth);

    // Perform the breach check first so its result is available.
    BreachCheckResult result = checkPasswordAgainstHIBP(password);

    // ============================================================
    // PRIVACY PROTECTION
    // ============================================================

    cout << "\n";
    printBoxTitle("PRIVACY PROTECTION", boxWidth);
    printEmptyBoxRow(boxWidth);

    printColoredBoxRow(
        "FULL PASSWORD : ",
        "[NEVER TRANSMITTED]",
        COLOR_GREEN,
        boxWidth
    );

    printEmptyBoxRow(boxWidth);

    printColoredBoxRow(
        "SHA-1 PREFIX  : ",
        result.hashPrefix,
        COLOR_CYAN,
        boxWidth
    );

    printEmptyBoxRow(boxWidth);

    printBoxTextRow("METHOD        : k-Anonymity", boxWidth);

    printEmptyBoxRow(boxWidth);
    printBoxBorder(boxWidth);

    // ============================================================
    // CONNECTION STATUS
    // ============================================================

    cout << "\n";
    printBoxTitle("CONNECTION STATUS", boxWidth);
    printEmptyBoxRow(boxWidth);

    if (result.connectedSuccessfully)
    {
        showHIBPSpinner("Connecting to HIBP server");
        printEmptyBoxRow(boxWidth);

        showHIBPSpinner("Requesting Hash matches");
        printEmptyBoxRow(boxWidth);

        showHIBPSpinner("Comparing Hash locally");
    }
    else
    {
        printColoredBoxRow(
            "Connecting to HIBP server          ",
            "[FAILED]",
            COLOR_RED,
            boxWidth
        );

        printEmptyBoxRow(boxWidth);

        printColoredBoxRow(
            "Requesting hash matches            ",
            "[SKIPPED]",
            COLOR_YELLOW,
            boxWidth
        );

        printEmptyBoxRow(boxWidth);

        printColoredBoxRow(
            "Comparing hash locally             ",
            "[SKIPPED]",
            COLOR_YELLOW,
            boxWidth
        );
    }

    printEmptyBoxRow(boxWidth);
    printBoxBorder(boxWidth);

    if (!result.connectedSuccessfully)
    {
        cout << "\n"
            << COLOR_RED
            << "  Could not connect to the Have I Been Pwned API."
            << COLOR_RESET
            << "\n";

        cout << "  Please check your internet connection and try again.\n";

        printFooter();
        return;
    }

    // ============================================================
    // BREACH RESULT
    // ============================================================

    cout << "\n";
    printBoxTitle("BREACH RESULT", boxWidth);
    printEmptyBoxRow(boxWidth);

    if (result.foundInBreach)
    {
        printColoredBoxRow(
            "STATUS       : ",
            "[COMPROMISED]",
            COLOR_RED,
            boxWidth
        );

        printEmptyBoxRow(boxWidth);

        string readableCount = formatReadableCount(result.occurrences);
        string occurrenceText = "OCCURRENCES  : " + readableCount;

        printBoxTextRow(occurrenceText, boxWidth);
        printEmptyBoxRow(boxWidth);
        printBoxBorder(boxWidth);

        // ========================================================
        // RISK EXPLANATION
        // ========================================================

        cout << "\n"
            << COLOR_CYAN
            << "  [ -- RISK EXPLANATION -- ]"
            << COLOR_RESET
            << "\n";

        cout << "  ---------------------------------------------\n\n";

        cout << "  This password appears in "
            << readableCount
            << " known breach records.\n";

        cout << "  Attackers may already include it in password lists.\n";
        cout << "  Treat this password as compromised.\n";

        // ========================================================
        // REQUIRED ACTION
        // ========================================================

        cout << "\n"
            << COLOR_CYAN
            << "  [ -- REQUIRED ACTION -- ]"
            << COLOR_RESET
            << "\n";

        cout << "  ---------------------------------------------\n\n";

        cout << "  "
            << COLOR_RED
            << "Change this password immediately on every account\n"
            << "  where it is currently used."
            << COLOR_RESET
            << "\n";
    }
    else
    {
        printColoredBoxRow(
            "STATUS       : ",
            "[NOT FOUND]",
            COLOR_GREEN,
            boxWidth
        );

        printEmptyBoxRow(boxWidth);
        printBoxTextRow("OCCURRENCES  : 0 known Breach Records", boxWidth);
        printEmptyBoxRow(boxWidth);
        printBoxBorder(boxWidth);

        // ========================================================
        // RISK EXPLANATION
        // ========================================================

        cout << "\n"
            << COLOR_CYAN
            << "  [ -- RISK EXPLANATION -- ]"
            << COLOR_RESET
            << "\n";

        cout << "  ---------------------------------------------\n\n";

        cout << "  This Password was not found in the current Breach Database.\n";
        cout << "  This does not guarantee that the password is completely safe.\n";
        cout << "  It may still be weak, reused, or vulnerable to guessing.\n";

        // ========================================================
        // RECOMMENDATIONb
        // ====================================================B====

        cout << "\n"
            << COLOR_CYAN
            << "  [ -- RECOMMENDATION -- ]"
            << COLOR_RESET
            << "\n";

        cout << "  ---------------------------------------------\n\n";

        cout << "  Keep it unique, use a Password Manager, and Enable MFA.\n";
    }
}