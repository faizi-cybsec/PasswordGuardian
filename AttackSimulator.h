/*
    ============================================================
    ATTACKSIMULATOR.H
    ============================================================
    IMPORTANT: This module NEVER performs any real password
    cracking or attacks. It only displays a fake, educational
    progress animation so students can see what each attack
    "looks like" conceptually, paired with the real crack-time
    estimates calculated in Entropy.cpp.
    ============================================================
*/

#pragma once

#include "PasswordAnalyzer.h"

// Runs the interactive "Attack Simulator" menu, letting the user
// pick which (fake, educational) attack type to simulate against
// a password they type in.
void attackSimulatorMenu();
