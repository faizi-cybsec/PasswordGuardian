/*
    ============================================================
    PASSWORD GENERATOR MODULE
    ============================================================
    This file is responsible for:

    1. Showing the password generator menu
    2. Reading and validating user input
    3. Generating secure random passwords
    4. Guaranteeing selected character types
    5. Preventing duplicate generated passwords
    6. Allowing optional detailed password analysis
    ============================================================
*/

#include "PasswordGenerator.h"   // GeneratorOptions and function declarations
#include "Utils.h"               // printBox() and other shared UI helpers
#include "PasswordAnalyzer.h"    // analyzePassword() and dashboard printing

#include <iomanip>
#include <random>      // random_device, mt19937, uniform_int_distribution
#include <algorithm>   // remove() and shuffle()
#include <iostream>    // cin and cout
#include <vector>      // stores generated passwords and guaranteed characters
#include <string>      // string
#include <limits>      // clears invalid input from cin

using namespace std;

// ============================================================
// RANDOM NUMBER GENERATOR
// ============================================================

// Returns one shared random-number generator.
// "static" means the generator is created only once and reused.
static mt19937& rng()
{
    static random_device rd;          // Gets a random starting seed
    static mt19937 generator(rd());   // Creates the random generator
    return generator;
}

// ============================================================
// INPUT HELPERS
// ============================================================

// Clears cin after invalid input, such as typing letters
// when the program expects a number.
static void clearInput()
{
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

// Repeatedly asks the user for a number until the number
// is inside the required minimum and maximum range.
static int askNumberInRange(
    const string& message,
    int minimum,
    int maximum
)
{
    int value;

    while (true)
    {
        cout << message;

        // Input is accepted only when it is a valid number
        // and lies inside the required range.
        if (cin >> value && value >= minimum && value <= maximum)
        {
            return value;
        }

        cout << "Invalid input. Enter a number from "
            << minimum << " to " << maximum << ".\n";

        clearInput();
    }
}

// Asks a yes/no question using 1 for Yes and 0 for No.
static bool askYesNo(const string& message)
{
    int choice;

    while (true)
    {
        cout << message << " (1 = Yes, 0 = No): ";

        if (cin >> choice && (choice == 0 || choice == 1))
        {
            // Returns true for 1 and false for 0.
            return choice == 1;
        }

        cout << "Invalid input. Enter 1 or 0.\n";
        clearInput();
    }
}

// Counts how many character categories are enabled.
// Example: uppercase + lowercase + digits = 3 selected types.
static int countSelectedTypes(const GeneratorOptions& options)
{
    int count = 0;

    if (options.useUpper)
    {
        count++;
    }

    if (options.useLower)
    {
        count++;
    }

    if (options.useDigits)
    {
        count++;
    }

    if (options.useSymbols)
    {
        count++;
    }

    return count;
}

// Validates settings entered in Custom mode.
static void validateOptions(GeneratorOptions& options)
{
    int selectedTypes = countSelectedTypes(options);

    // If the user disables all character types, lowercase letters
    // are enabled automatically so a password can still be made.
    if (selectedTypes == 0)
    {
        cout << "\nNo character type was selected.\n";
        cout << "Lowercase letters were enabled automatically.\n";

        options.useLower = true;
        selectedTypes = 1;
    }

    // Protect against passwords shorter than the allowed minimum.
    if (options.length < 4)
    {
        cout << "\nMinimum password length is 4 characters.\n";
        options.length = 4;
    }

    // Prevent extremely large passwords.
    if (options.length > 64)
    {
        cout << "\nMaximum password length is 64 characters.\n";
        options.length = 64;
    }

    // The password must be long enough to include at least one
    // character from every selected category.
    if (options.length < selectedTypes)
    {
        cout << "\nThe selected length is too short for all enabled types.\n";
        cout << "Length changed to " << selectedTypes << ".\n";

        options.length = selectedTypes;
    }
}

// ============================================================
// SINGLE PASSWORD GENERATION
// ============================================================

string generatePasswordWithOptions(const GeneratorOptions& options)
{
    // Separate character sets make it easy to enable or disable
    // individual categories.
    string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string lower = "abcdefghijklmnopqrstuvwxyz";
    string digits = "0123456789";
    string symbols = "!@#$%^&*()-_=+[]{};:,.<>?/|~";

    // Remove visually confusing characters when requested.
    // Examples: zero and capital O, one and lowercase l.
    if (options.avoidAmbiguous)
    {
        const string ambiguous = "0O1lI";

        for (char character : ambiguous)
        {
            upper.erase(
                remove(upper.begin(), upper.end(), character),
                upper.end()
            );

            lower.erase(
                remove(lower.begin(), lower.end(), character),
                lower.end()
            );

            digits.erase(
                remove(digits.begin(), digits.end(), character),
                digits.end()
            );

            symbols.erase(
                remove(symbols.begin(), symbols.end(), character),
                symbols.end()
            );
        }
    }

    // "pool" contains every character that may be used.
    string pool;

    // Stores one guaranteed character from each enabled category.
    // This prevents a generated password from accidentally missing
    // a selected type.
    vector<char> guaranteedCharacters;

    // Small local function that selects one random character
    // from a supplied string.
    auto pickRandomCharacter = [&](const string& characters) -> char
        {
            uniform_int_distribution<size_t> distribution(
                0,
                characters.size() - 1
            );

            return characters[distribution(rng())];
        };

    // Add selected character groups to the main pool.
    // Also save one guaranteed character from each selected group.
    if (options.useUpper && !upper.empty())
    {
        pool += upper;
        guaranteedCharacters.push_back(pickRandomCharacter(upper));
    }

    if (options.useLower && !lower.empty())
    {
        pool += lower;
        guaranteedCharacters.push_back(pickRandomCharacter(lower));
    }

    if (options.useDigits && !digits.empty())
    {
        pool += digits;
        guaranteedCharacters.push_back(pickRandomCharacter(digits));
    }

    if (options.useSymbols && !symbols.empty())
    {
        pool += symbols;
        guaranteedCharacters.push_back(pickRandomCharacter(symbols));
    }

    // Safety fallback in case all categories are somehow disabled.
    if (pool.empty())
    {
        pool = lower;
        guaranteedCharacters.push_back(pickRandomCharacter(lower));
    }

    string password;

    // reserve() prepares enough memory for the complete password.
    password.reserve(options.length);

    // Creates random index values for the combined character pool.
    uniform_int_distribution<size_t> poolDistribution(
        0,
        pool.size() - 1
    );

    // Fill the password with random characters from the full pool.
    for (int i = 0; i < options.length; i++)
    {
        password.push_back(pool[poolDistribution(rng())]);
    }

    // Overwrite the first positions with guaranteed characters.
    // This ensures every selected category appears at least once.
    for (
        size_t i = 0;
        i < guaranteedCharacters.size() && i < password.size();
        i++
        )
    {
        password[i] = guaranteedCharacters[i];
    }

    // Shuffle the password so guaranteed characters are not always
    // found at predictable positions near the beginning.
    shuffle(password.begin(), password.end(), rng());

    return password;
}

// ============================================================
// MULTIPLE PASSWORD GENERATION
// ============================================================

// Checks whether a newly generated password already exists
// inside the current vector.
static bool passwordAlreadyExists(
    const vector<string>& passwords,
    const string& newPassword
)
{
    for (const string& password : passwords)
    {
        if (password == newPassword)
        {
            return true;
        }
    }

    return false;
}

// Generates the requested number of unique passwords.
vector<string> generateMultiplePasswords(
    const GeneratorOptions& options,
    int howMany
)
{
    vector<string> passwords;

    if (howMany <= 0)
    {
        return passwords;
    }

    // Prepares enough vector capacity for all passwords.
    passwords.reserve(howMany);

    // Continue generating until the requested number of unique
    // passwords has been stored.
    while (static_cast<int>(passwords.size()) < howMany)
    {
        string newPassword = generatePasswordWithOptions(options);

        if (!passwordAlreadyExists(passwords, newPassword))
        {
            passwords.push_back(newPassword);
        }
    }

    return passwords;
}

// ============================================================
// DISPLAY HELPERS
// ============================================================

// Centers text inside a fixed-width row.
static string centerGeneratorText(
    const string& text,
    int width
)
{
    if (static_cast<int>(text.length()) >= width)
    {
        return text.substr(0, width);
    }

    int totalSpaces =
        width - static_cast<int>(text.length());

    int leftSpaces = totalSpaces / 2;
    int rightSpaces = totalSpaces - leftSpaces;

    return string(leftSpaces, ' ')
        + text
        + string(rightSpaces, ' ');
}

// Prints the top or bottom border used by generator boxes.
static void printGeneratorBorder(int width)
{
    cout << COLOR_WHITE
        << "  +"
        << string(width, '-')
        << "+"
        << COLOR_RESET
        << "\n";
}

// Prints an empty row inside a generator box.
static void printGeneratorEmptyRow(int width)
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

// Prints a centered title row.
static void printGeneratorTitleRow(
    const string& title,
    int width,
    const string& color
)
{
    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << color
        << centerGeneratorText(title, width)
        << COLOR_RESET
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a normal text row inside a fixed-width box.
static void printGeneratorTextRow(
    const string& text,
    int width,
    const string& color = COLOR_RESET
)
{
    const int contentWidth = width - 4;

    string displayText = text;

    if (static_cast<int>(displayText.length()) > contentWidth)
    {
        displayText = displayText.substr(0, contentWidth);
    }

    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << "  "
        << color
        << left
        << setw(contentWidth)
        << displayText
        << COLOR_RESET
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints a label and value with proper color and alignment.
static void printGeneratorInfoRow(
    const string& label,
    const string& value,
    int width,
    const string& valueColor = COLOR_RESET,
    int labelWidth = 11
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

    string shownValue = value;

    if (static_cast<int>(shownValue.length()) > valueWidth)
    {
        shownValue = shownValue.substr(0, valueWidth);
    }

    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << "  "
        << COLOR_CYAN
        << left
        << setw(labelWidth)
        << shownLabel
        << COLOR_RESET
        << separator
        << valueColor
        << left
        << setw(valueWidth)
        << shownValue
        << COLOR_RESET
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints one preset row inside the generator menu box.
static void printGeneratorPresetRow(
    const string& number,
    const string& mode,
    const string& length,
    const string& description,
    const string& modeColor,
    int width
)
{
    const int contentWidth = width - 4;

    const int numberWidth = 4;
    const int modeWidth = 11;
    const int lengthWidth = 11;
    const int descriptionWidth =
        contentWidth -
        numberWidth -
        modeWidth -
        lengthWidth;

    string shownDescription = description;

    if (static_cast<int>(shownDescription.length()) >
        descriptionWidth)
    {
        shownDescription =
            shownDescription.substr(0, descriptionWidth);
    }

    cout << COLOR_WHITE
        << "  |"
        << COLOR_RESET
        << "  "
        << COLOR_CYAN
        << left
        << setw(numberWidth)
        << ("[" + number + "]")
        << COLOR_RESET
        << modeColor
        << left
        << setw(modeWidth)
        << mode
        << COLOR_RESET
        << COLOR_WHITE
        << left
        << setw(lengthWidth)
        << length
        << left
        << setw(descriptionWidth)
        << shownDescription
        << COLOR_RESET
        << "  "
        << COLOR_WHITE
        << "|"
        << COLOR_RESET
        << "\n";
}

// Prints the password generator menu.
static void printGeneratorMenu()
{
    const int menuWidth = 58;

    cout << "\n";

    printGeneratorBorder(menuWidth);

    printGeneratorTitleRow(
        "PASSWORD GENERATOR",
        menuWidth,
        COLOR_CYAN
    );

    printGeneratorTitleRow(
        "Secure Random Password Creation",
        menuWidth,
        COLOR_YELLOW
    );

    printGeneratorBorder(menuWidth);
    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "1",
        "EASY",
        "12 chars",
        "Letters + Digits",
        COLOR_GREEN,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "2",
        "MEDIUM",
        "16 chars",
        "Letters + Digits + Symbols",
        COLOR_CYAN,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "3",
        "STRONG",
        "20 chars",
        "All Character Types",
        COLOR_YELLOW,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "4",
        "MILITARY",
        "24 chars",
        "No Ambiguous Characters",
        COLOR_RED,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "5",
        "CUSTOM",
        "",
        "Choose your own Settings",
        COLOR_YELLOW,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);

    printGeneratorPresetRow(
        "0",
        "BACK",
        "",
        "Return to Main Menu",
        COLOR_WHITE,
        menuWidth
    );

    printGeneratorEmptyRow(menuWidth);
    printGeneratorBorder(menuWidth);

    cout << "\n";
}

// Converts the selected menu option into a readable mode name.
static string getModeName(int choice)
{
    switch (choice)
    {
    case 1:
        return "EASY";

    case 2:
        return "MEDIUM";

    case 3:
        return "STRONG";

    case 4:
        return "MILITARY";

    case 5:
        return "CUSTOM";

    default:
        return "UNKNOWN";
    }
}

// Returns the color used for the selected mode.
static string getModeColor(int choice)
{
    switch (choice)
    {
    case 1:
        return COLOR_GREEN;

    case 2:
        return COLOR_CYAN;

    case 3:
        return COLOR_YELLOW;

    case 4:
        return COLOR_RED;

    case 5:
        return COLOR_YELLOW;

    default:
        return COLOR_WHITE;
    }
}

// Builds a short description of the selected character groups.
static string getCharacterTypes(
    const GeneratorOptions& options
)
{
    string description;

    if (options.useUpper)
    {
        description += "Upper";
    }

    if (options.useLower)
    {
        if (!description.empty())
        {
            description += ", ";
        }

        description += "Lower";
    }

    if (options.useDigits)
    {
        if (!description.empty())
        {
            description += ", ";
        }

        description += "Digits";
    }

    if (options.useSymbols)
    {
        if (!description.empty())
        {
            description += ", ";
        }

        description += "Symbols";
    }

    return description;
}

// Prints the generated password.
// Long Custom passwords continue onto extra rows.
static void printPasswordRows(
    const string& password,
    int width
)
{
    const int contentWidth = width - 4;
    const int labelWidth = 11;
    const string separator = " : ";

    int firstValueWidth =
        contentWidth -
        labelWidth -
        static_cast<int>(separator.length());

    size_t position = 0;
    bool firstLine = true;

    while (position < password.length())
    {
        int valueWidth = firstValueWidth;
        string part = password.substr(position, valueWidth);

        cout << COLOR_WHITE
            << "  |"
            << COLOR_RESET
            << "  ";

        if (firstLine)
        {
            cout << COLOR_CYAN
                << left
                << setw(labelWidth)
                << "PASSWORD"
                << COLOR_RESET
                << separator;
        }
        else
        {
            cout << string(labelWidth, ' ')
                << string(separator.length(), ' ');
        }

        cout << COLOR_GREEN
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
    }
}

// Displays one generated password using the dashboard layout.
static void printGeneratedPassword(
    const string& password,
    int number,
    const string& modeName,
    const string& modeColor,
    const GeneratorOptions& options
)
{
    const int boxWidth = 50;

    cout << "\n";

    printGeneratorBorder(boxWidth);

    printGeneratorTitleRow(
        "GENERATED PASSWORD #" + to_string(number),
        boxWidth,
        COLOR_CYAN
    );

    printGeneratorBorder(boxWidth);
    printGeneratorEmptyRow(boxWidth);

    printPasswordRows(password, boxWidth);

    printGeneratorEmptyRow(boxWidth);

    printGeneratorInfoRow(
        "MODE",
        modeName,
        boxWidth,
        modeColor
    );

    printGeneratorEmptyRow(boxWidth);

    printGeneratorInfoRow(
        "LENGTH",
        to_string(password.length()) + " characters",
        boxWidth,
        COLOR_GREEN
    );

    printGeneratorEmptyRow(boxWidth);

    printGeneratorInfoRow(
        "CHARACTER",
        getCharacterTypes(options),
        boxWidth,
        COLOR_WHITE
    );

    printGeneratorEmptyRow(boxWidth);

    printGeneratorInfoRow(
        "AMBIGUOUS",
        options.avoidAmbiguous
        ? "Removed"
        : "Allowed",
        boxWidth,
        options.avoidAmbiguous
        ? COLOR_GREEN
        : COLOR_YELLOW
    );

    printGeneratorEmptyRow(boxWidth);
    printGeneratorBorder(boxWidth);
}

// Lets the user choose whether to open the full security dashboard.
static void showGeneratedPasswordOptions(
    const string& password
)
{
    cout << "\n";

    cout << "  "
        << COLOR_CYAN
        << ">> NEXT ACTION"
        << COLOR_RESET
        << "\n\n";

    cout << "     "
        << COLOR_CYAN
        << "[1]"
        << COLOR_RESET
        << " Detailed security analysis\n";

    cout << "     "
        << COLOR_CYAN
        << "[0]"
        << COLOR_RESET
        << " Continue\n\n";

    int choice = askNumberInRange(
        "  Enter Choice: ",
        0,
        1
    );

    if (choice == 1)
    {
        PasswordAnalysis analysis =
            analyzePassword(password);

        printPasswordDashboard(analysis);
    }
}

// ============================================================
// MAIN PASSWORD GENERATOR MENU
// ============================================================

void passwordGeneratorMenu()
{
    // Keep showing the generator menu until the user chooses 0.
    while (true)
    {
        printGeneratorMenu();

        int choice = askNumberInRange(
            COLOR_WHITE + string("Enter Choice: ") + COLOR_RESET,
            0,
            5
        );
        cout << "\n";

        if (choice == 0)
        {
            return;
        }

        // Stores the settings for the selected preset or Custom mode.
        GeneratorOptions options;

        // Stores the readable preset name and color for the result box.
        string modeName = getModeName(choice);
        string modeColor = getModeColor(choice);

        switch (choice)
        {
        case 1:
            // Easy: letters and digits, no symbols.
            options.length = 12;
            options.useLower = true;
            options.useUpper = true;
            options.useDigits = true;
            options.useSymbols = false;
            options.avoidAmbiguous = false;
            break;

        case 2:
            // Medium: all main character categories.
            options.length = 16;
            options.useLower = true;
            options.useUpper = true;
            options.useDigits = true;
            options.useSymbols = true;
            options.avoidAmbiguous = false;
            break;

        case 3:
            // Strong: same character types as Medium,
            // but with a longer length.
            options.length = 20;
            options.useLower = true;
            options.useUpper = true;
            options.useDigits = true;
            options.useSymbols = true;
            options.avoidAmbiguous = false;
            break;

        case 4:
            // Military: longest preset and confusing characters removed.
            options.length = 24;
            options.useLower = true;
            options.useUpper = true;
            options.useDigits = true;
            options.useSymbols = true;
            options.avoidAmbiguous = true;
            break;

        case 5:
            // Custom mode lets the user choose every setting.
            cout << "\n";
            cout << "  -- CUSTOM GENERATOR SETTINGS --\n\n";

            options.length = askNumberInRange(
                "Password length (4-64): ",
                4,
                64
            );

            options.useUpper =
                askYesNo("Use uppercase letters?");

            options.useLower =
                askYesNo("Use lowercase letters?");

            options.useDigits =
                askYesNo("Use numbers?");

            options.useSymbols =
                askYesNo("Use symbols?");

            options.avoidAmbiguous =
                askYesNo("Avoid ambiguous characters?");

            validateOptions(options);
            break;
        }


        // Ask how many unique passwords should be generated.
        int howMany = askNumberInRange(
            COLOR_WHITE +
            string("How many passwords to generate? (1-10): ") +
            COLOR_RESET,
            1,
            10
        );

        vector<string> passwords =
            generateMultiplePasswords(options, howMany);

        // Display each generated password one at a time.
        for (size_t i = 0; i < passwords.size(); i++)
        {
            printGeneratedPassword(
                passwords[i],
                static_cast<int>(i) + 1,
                modeName,
                modeColor,
                options
            );

            showGeneratedPasswordOptions(passwords[i]);
        }

        cout << "\nPress Enter to continue...";

        // Remove the leftover newline from the previous cin input,
        // then wait for the user to press Enter.
        clearInput();
        cin.get();
    }
}