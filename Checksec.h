#pragma once

#ifdef __linux__
#include "windows-deps.h"
#define EXPORT
#else
#ifdef _WINCHECKSEC_STANDALONE
#define EXPORT
#else
#ifdef _WINCHECKSEC_EXPORT
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif
#endif
#include <Windows.h>
#endif

#include <iostream>
#include <string>

#define _PEPARSE_WINDOWS_CONFLICTS
#include <parser-library/parse.h>

#include "json.hpp"
using json = nlohmann::json;

using namespace std;

namespace checksec {

class EXPORT ChecksecError : public std::runtime_error {
public:
    ChecksecError(const char* what)
        : std::runtime_error(what)
    {
    }
};

class EXPORT Checksec {
public:
    Checksec(string filepath);

    json toJson() const;

    const bool isDynamicBase() const;
    const bool isASLR() const;
    const bool isHighEntropyVA() const;
    const bool isForceIntegrity() const;
    const bool isNX() const;
    const bool isIsolation() const;
    const bool isSEH() const;
    const bool isCFG() const;
    const bool isAuthenticode() const;
    const bool isRFG() const;
    const bool isSafeSEH() const;
    const bool isGS() const;
    const bool isDotNET() const;

    operator json() const;
    friend ostream& operator<<(ostream& os, Checksec&);

private:
    string filepath_;
    uint16_t imageCharacteristics_ = 0;
    uint16_t dllCharacteristics_ = 0;
    uint32_t loadConfigSize_ = 0;
    uint32_t loadConfigGuardFlags_ = 0;
    uint64_t loadConfigSEHandlerTable_ = 0;
    uint64_t loadConfigSEHandlerCount_ = 0;
    uint64_t loadConfigSecurityCookie_ = 0;
    peparse::data_directory clrConfig_ = { 0 };
};

} // namespace checksec
