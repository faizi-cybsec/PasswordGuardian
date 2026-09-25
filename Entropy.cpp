/*
    ============================================================
    ENTROPY.CPP
    ============================================================
    See Entropy.h for an explanation of what each function does.
    ============================================================
*/

#include "Entropy.h"
#include "PasswordAnalyzer.h" // for hasUppercase/hasLowercase/hasDigit/hasSpecialChar
#include <cmath>
#include <sstream>
#include <iomanip>

using namespace std;

// Calculates THEORETICAL entropy in bits using the classic formula:
//   entropy = length * log2(poolSize)
//
// This assumes every character was chosen randomly from the detected
// character pool. Dictionary words and common patterns can have much
// lower practical resistance, which is handled by PasswordAnalyzer.cpp.
double calculateEntropyBits(const string& password)
{
    if (password.empty())
    {
        return 0.0;
    }

    int poolSize = 0;

    if (hasLowercase(password))
    {
        poolSize += 26;
    }
    if (hasUppercase(password))
    {
        poolSize += 26;
    }
    if (hasDigit(password))
    {
        poolSize += 10;
    }
    if (hasSpecialChar(password))
    {
        poolSize += 32;
    }

    // If somehow no character type was detected, avoid log2(0).
    if (poolSize == 0)
    {
        poolSize = 1;
    }

    double bitsPerCharacter = log2(static_cast<double>(poolSize));
    return bitsPerCharacter * static_cast<double>(password.length());
}

// Turns a theoretical entropy value into a short label.
string classifyComplexity(double entropyBits)
{
    if (entropyBits < 28)
    {
        return "Very Low";
    }
    else if (entropyBits < 36)
    {
        return "Low";
    }
    else if (entropyBits < 60)
    {
        return "Medium";
    }
    else if (entropyBits < 80)
    {
        return "High";
    }
    else
    {
        return "Very High";
    }
}

// Builds a readable theoretical search-space string, e.g. 9.5 x 10^15.
// The search space is 2^entropyBits and is written in scientific notation.
string buildSearchSpaceText(double entropyBits)
{
    double exponent = entropyBits * log10(2.0);

    int wholeExponent = static_cast<int>(exponent);
    double remainder = exponent - wholeExponent;
    double mantissa = pow(10.0, remainder);

    ostringstream output;
    output << fixed << setprecision(2)
        << mantissa << " x 10^" << wholeExponent;

    return output.str();
}

// Builds the full EntropyResult for a password.
EntropyResult calculateEntropyDetails(const string& password)
{
    EntropyResult result;

    result.entropyBits = calculateEntropyBits(password);
    result.complexityLabel = classifyComplexity(result.entropyBits);
    result.searchSpaceText = buildSearchSpaceText(result.entropyBits);

    result.poolSize = 0;

    if (hasLowercase(password))
    {
        result.poolSize += 26;
    }
    if (hasUppercase(password))
    {
        result.poolSize += 26;
    }
    if (hasDigit(password))
    {
        result.poolSize += 10;
    }
    if (hasSpecialChar(password))
    {
        result.poolSize += 32;
    }

    return result;
}

// Explains the theoretical entropy number in plain English.
// Pattern and dictionary checks must still be considered separately.
string explainEntropy(double entropyBits)
{
    string label = classifyComplexity(entropyBits);

    if (label == "Very Low")
    {
        return "The theoretical entropy is very low. Even without considering "
            "dictionary words or patterns, the possible search space is small.";
    }
    else if (label == "Low")
    {
        return "The theoretical entropy is low. Automated guessing may search "
            "the possible character space with relatively little effort.";
    }
    else if (label == "Medium")
    {
        return "The theoretical entropy is moderate. This value assumes the "
            "characters were selected randomly, so detected words or patterns "
            "can reduce the practical security significantly.";
    }
    else if (label == "High")
    {
        return "The theoretical entropy is high. This provides good brute-force "
            "resistance only when the password is not based on predictable "
            "words, personal data, or common patterns.";
    }
    else
    {
        return "The theoretical entropy is very high. This provides strong "
            "brute-force resistance when the password is randomly generated "
            "and contains no predictable structure.";
    }
}

// Converts a number of seconds into a readable duration string.
static string formatDuration(long double seconds)
{
    stringstream output;
    output << fixed << setprecision(1);

    if (seconds < 1.0L)
    {
        return "Instantly";
    }
    else if (seconds < 60.0L)
    {
        output << seconds << " seconds";
    }
    else if (seconds < 3600.0L)
    {
        output << seconds / 60.0L << " minutes";
    }
    else if (seconds < 86400.0L)
    {
        output << seconds / 3600.0L << " hours";
    }
    else if (seconds < 31536000.0L)
    {
        output << seconds / 86400.0L << " days";
    }
    else
    {
        long double years = seconds / 31536000.0L;

        if (years < 1000.0L)
        {
            output << years << " years";
        }
        else if (years < 1000000.0L)
        {
            output << years / 1000.0L << " thousand years";
        }
        else if (years < 1000000000.0L)
        {
            output << years / 1000000.0L << " million years";
        }
        else if (years < 1000000000000.0L)
        {
            output << years / 1000000000.0L << " billion years";
        }
        else if (years < 1000000000000000.0L)
        {
            output << years / 1000000000000.0L << " trillion years";
        }
        else if (years < 1000000000000000000.0L)
        {
            output << years / 1000000000000000.0L << " quadrillion years";
        }
        else
        {
            return "PRACTICALLY IMPOSSIBLE";
        }
    }

    return output.str();
}

// Estimates crack time under each simulated attack type.
//
// These are simplified educational estimates. The brute-force values
// use the theoretical character search space. Dictionary and hybrid
// results represent practical attacks that try common choices first.
//
// Guess speeds used:
//   Online attack       : 10 guesses/second
//   Offline attack      : 1,000,000,000 guesses/second
//   GPU attack          : 10,000,000,000 guesses/second
//   Dictionary attack   : immediate for common passwords
//   Hybrid attack       : faster for dictionary-based mutations
//   Brute-force attack  : full theoretical character space
CrackTimeEstimates estimateCrackTimes(
    double entropyBits,
    bool isDictionaryWord,
    bool isCommonPassword
)
{
    CrackTimeEstimates estimates;

    long double totalCombinations =
        pow(2.0L, static_cast<long double>(entropyBits));

    // On average, half of the total search space is tested.
    long double averageCombinations = totalCombinations / 2.0L;

    // Online rate-limited brute force: about 10 guesses/second.
    long double onlineSeconds = averageCombinations / 10.0L;
    estimates.onlineAttack = formatDuration(onlineSeconds);

    // Fast offline cracking: about 1 billion guesses/second.
    long double offlineSeconds = averageCombinations / 1000000000.0L;
    estimates.offlineAttack = formatDuration(offlineSeconds);

    // Dedicated GPU estimate: about 10 billion guesses/second.
    long double gpuSeconds = averageCombinations / 10000000000.0L;
    estimates.gpuAttack = formatDuration(gpuSeconds);

    // Dictionary attack.
    if (isCommonPassword)
    {
        estimates.dictionaryAttack =
            "Instantly (found in common password list)";
    }
    else if (isDictionaryWord)
    {
        estimates.dictionaryAttack =
            "Seconds (based on a known dictionary word)";
    }
    else
    {
        estimates.dictionaryAttack = "No direct dictionary match";
    }

    // Hybrid attack: dictionary word plus common mutations.
    if (isDictionaryWord || isCommonPassword)
    {
        estimates.hybridAttack =
            "Minutes (dictionary word with simple mutations)";
    }
    else
    {
        long double hybridSeconds = averageCombinations / 10000000.0L;
        estimates.hybridAttack = formatDuration(hybridSeconds);
    }

    // Full theoretical brute-force search.
    long double bruteForceSeconds = averageCombinations / 1000000000.0L;
    estimates.bruteForceAttack = formatDuration(bruteForceSeconds);

    return estimates;
}