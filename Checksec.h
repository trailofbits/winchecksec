#pragma once

// clang-format off
#ifdef _WIN32
    #ifdef _WINCHECKSEC_STANDALONE
        #define EXPORT
    #else
        #ifdef _WINCHECKSEC_EXPORT
          #define EXPORT __declspec(dllexport)
        #else
          #define EXPORT __declspec(dllimport)
        #endif
    #endif
#else
    #define EXPORT
#endif
// clang-format on

#include <iostream>
#include <string>

#include <parser-library/parse.h>

#include "vendor/json.hpp"
using json = nlohmann::json;

using namespace std;

namespace checksec {

class EXPORT ChecksecError : public std::runtime_error {
   public:
    ChecksecError(const char* what) : std::runtime_error(what) {}
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
#ifdef _WIN32
    const bool isAuthenticode() const;
#endif
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
    peparse::data_directory clrConfig_ = {0};
};

}  // namespace checksec
