/*
    ============================================================
    PASSWORDGENERATOR.H
    ============================================================
    This keeps the original random password generator (same
    core idea: build a pool of allowed characters, guarantee one
    of each required type, fill the rest randomly, then shuffle)
    but upgrades it with:
      - Named difficulty levels (Easy, Medium, Strong, Military)
      - A Custom mode with individual on/off options
      - Support for generating multiple passwords at once
      - An option to avoid visually ambiguous characters (0/O, 1/l/I)
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// Options that control exactly which characters can be used when
// generating a password.
struct GeneratorOptions
{
    int length = 12;
    bool useUpper = true;
    bool useLower = true;
    bool useDigits = true;
    bool useSymbols = true;
    bool avoidAmbiguous = false; // removes 0/O, 1/l/I, etc. if true
};

// Generates one random password using the given options.
// This is the upgraded version of the original generatePassword()
// function - same technique, more control.
std::string generatePasswordWithOptions(const GeneratorOptions &options);

// Generates several random passwords at once using the same options
std::vector<std::string> generateMultiplePasswords(const GeneratorOptions &options, int howMany);

// Runs the interactive "Password Generator" menu shown from the
// main menu, including the Easy/Medium/Strong/Military/Custom levels.
void passwordGeneratorMenu();
