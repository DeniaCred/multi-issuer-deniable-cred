#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <utility>

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

#endif
