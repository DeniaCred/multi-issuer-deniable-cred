#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <utility>
#include <sstream>
#include "Algorithm/pairing_3.h"

static const char* ANSI_RESET  = "\033[0m";
static const char* ANSI_RED    = "\033[31m";
static const char* ANSI_GREEN  = "\033[32m";
static const char* ANSI_YELLOW = "\033[33m";
static const char* ANSI_BLUE   = "\033[34m";
static const char* ANSI_CYAN   = "\033[36m";
static const char* ANSI_BOLD   = "\033[1m";

extern std::vector<std::pair<std::string, double>> g_execution_times;

inline std::string timingLabel(const std::string& base, const std::string& context = "") {
    return context.empty() ? base : base + "_" + context;
}

inline std::string scalarToString(const Big& value) {
    std::ostringstream out;
    out << value;
    return out.str();
}

// The prototype derives ppHash from the concrete public pairing bases and
// scalar order used in the current execution.
inline std::string deriveProtocolParameterDigest(PFC* pfc, const G1& g1, const G2& g2) {
    pfc->start_hash();
    pfc->add_to_hash((char*)"multi-issuer-deniable-cred/pp/v1");
    pfc->add_to_hash(g1);
    pfc->add_to_hash(g2);
    Big order = pfc->order();
    pfc->add_to_hash(order);
    return scalarToString(pfc->finish_hash_to_group() % order);
}

// This textual encoding is included in ctx in addition to hashing pk_V in the
// Fiat--Shamir statements themselves.
inline std::string encodeG2ForContext(const G2& point) {
    std::ostringstream out;
    out << point.g;
    return out.str();
}

#endif
