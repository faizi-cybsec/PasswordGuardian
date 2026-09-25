/*
    ============================================================
    HIBP.H
    ============================================================
    This file contains:
      1. The original hand-written SHA-1 implementation (kept
         exactly as it worked before - no external crypto
         libraries are used).
      2. The "Have I Been Pwned" breach check, using the same
         k-Anonymity approach as before: only the first 5
         characters of the SHA-1 hash are ever sent to the API,
         so the real password never leaves the computer.

    The breach check has been upgraded to show more information
    (connection status, a privacy explanation, occurrence count,
    a risk explanation and a recommendation) but the underlying
    logic is unchanged.
    ============================================================
*/

#pragma once

#include <string>

// Left-rotate a 32-bit number by "bits" positions (used inside SHA-1)
unsigned int leftRotate(unsigned int value, unsigned int bits);

// Takes a normal text password and returns its SHA-1 hash as an
// uppercase hex string (this is what the HIBP API expects).
std::string sha1Hash(const std::string &input);

// Runs a system command (used to call "curl") and returns its
// console output as a string.
std::string runSystemCommand(const std::string &command);

// Holds the result of a single Have I Been Pwned lookup
struct BreachCheckResult
{
    bool connectedSuccessfully = false;
    bool foundInBreach = false;
    int occurrences = 0;
    std::string hashPrefix;   // The 5 characters that were sent to the API
    std::string hashSuffix;   // The rest of the hash, kept only locally
};

// Sends only the SHA-1 hash prefix to the Have I Been Pwned API and
// checks whether the given password's hash suffix appears in the
// returned list. This never sends the full password or full hash.
BreachCheckResult checkPasswordAgainstHIBP(const std::string &password);

// Prints a full, upgraded breach report for one password (connection
// status, privacy explanation, occurrence count, risk explanation and
// recommendation). This is the function called from the main menu.
void checkBreachDatabase();
