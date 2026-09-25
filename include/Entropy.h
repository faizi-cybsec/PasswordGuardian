/*
    ============================================================
    ENTROPY.H
    ============================================================
    Password entropy is a way of measuring how unpredictable a
    password is, measured in "bits". The more bits, the bigger
    the search space an attacker has to try before finding the
    password by guessing.

    This file also estimates how long it would take to crack a
    password under different kinds of attacks (online, offline,
    GPU, dictionary, hybrid, brute force).

    NOTE: These numbers are educational estimates, not exact
    science. Real crack times depend on hardware, the attacker's
    method, and whether the password is stored using a slow
    hashing algorithm like bcrypt. We use simple, well-known
    guesses-per-second figures to keep the math beginner-friendly.
    ============================================================
*/

#pragma once

#include <string>

// Holds the result of an entropy calculation for one password.
struct EntropyResult
{
    double entropyBits = 0.0;      // Entropy in bits
    int poolSize = 0;              // Size of the character pool used
    std::string complexityLabel;   // "Very Low" .. "Very High"
    std::string searchSpaceText;   // Human readable search space, e.g. "9.5 x 10^15"
};

// Holds crack time estimates for every attack type the assistant simulates.
struct CrackTimeEstimates
{
    std::string onlineAttack;      // slow, rate-limited login attempts
    std::string offlineAttack;     // fast offline hash cracking
    std::string gpuAttack;         // GPU-accelerated cracking
    std::string dictionaryAttack;  // trying real words / leaked passwords first
    std::string hybridAttack;      // dictionary words + mutations
    std::string bruteForceAttack;  // trying every possible combination
};

// Calculates the entropy (in bits) of a password based on which
// character types it uses and how long it is.
double calculateEntropyBits(const std::string &password);

// Builds a full EntropyResult (bits, pool size, complexity label,
// and a readable search space string) for a password.
EntropyResult calculateEntropyDetails(const std::string &password);

// Turns an entropy value into a short human explanation of what
// it means, so the user learns something instead of just seeing
// a number.
std::string explainEntropy(double entropyBits);

// Estimates crack time under each attack type, using the
// password's entropy and whether it was flagged as a dictionary
// word or common password (dictionary/hybrid attacks are much
// faster against those).
CrackTimeEstimates estimateCrackTimes(double entropyBits, bool isDictionaryWord, bool isCommonPassword);

// Converts a number of seconds into a readable string such as
// "3 days", "42 years" or "2.1 million years".
std::string formatDuration(double seconds);
