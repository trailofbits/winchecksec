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
#include <optional>

#include <parser-library/parse.h>

#include "vendor/json.hpp"
using json = nlohmann::json;

namespace checksec {

#define REPORT_EXPLAIN(presence, description, explanation) \
    { MitigationPresence::presence, description, explanation }
#define REPORT(presence, description) \
    REPORT_EXPLAIN(presence, description, std::nullopt)

constexpr const char kDynamicBaseDescription[] =
    "Binaries with dynamic base support can be "
    "dynamically rebased, enabling ASLR.";

constexpr const char kASLRDescription[] =
    "Binaries with ASLR support have randomized virtual memory layouts. "
    "ASLR is enabled by dynamic base support (without stripped relocation "
    "entries) or by using a managed runtime like .NET.";

constexpr const char kHighEntropyVADescription[] =
    "Binaries with high entropy virtual address support can leverage more of "
    "the virtual memory space to strengthen ASLR.";

constexpr const char kForceIntegrityDescription[] =
    "Binaries with force integrity checking enabled perform additional "
    "Authenticode signing checks, including page hash checks.";

constexpr const char kNXDescription[] =
    "Binaries with NX support can be run with hardware-enforced memory "
    "permissions (i.e., hardware DEP).";

constexpr const char kIsolationDescription[] =
    "Binaries with isolation support cause the Windows loader to perform "
    "a manifest lookup on program load.";

constexpr const char kSEHDescription[] =
    "Binaries with SEH support can use structured exception handlers.";

constexpr const char kCFGDescription[] =
    "Binaries with CFG enabled have additional protections on indirect calls.";

constexpr const char kAuthenticodeDescription[] =
    "Binaries with Authenticode signatures are verified at load time.";

constexpr const char kRFGDescription[] =
    "Binaries with RFG enabled have additional return-oriented-programming "
    "protections.";

constexpr const char kSafeSEHDescription[] =
    "Binaries with SafeSEH enabled have additional protections for stack-based "
    "structured exception handlers.";

constexpr const char kGSDescription[] =
    "Binaries with GS enabled have additional protections against stack-based "
    "buffer overflows.";

constexpr const char kDotNETDescription[] =
    ".NET binaries run in a managed environment with many default mitigations.";

enum class EXPORT MitigationPresence {
    Present,
    NotPresent,
    NotApplicable,
    NotImplemented,
};

class EXPORT ChecksecError : public std::runtime_error {
   public:
    ChecksecError(const char* what) : std::runtime_error(what) {}
};

struct EXPORT MitigationReport {
    MitigationPresence presence;
    std::string description;
    std::optional<std::string> explanation;

    operator bool() const { return presence == MitigationPresence::Present; }
};

class EXPORT Checksec {
   public:
    Checksec(std::string filepath);

    json toJson() const;

    const MitigationReport isDynamicBase() const;
    const MitigationReport isASLR() const;
    const MitigationReport isHighEntropyVA() const;
    const MitigationReport isForceIntegrity() const;
    const MitigationReport isNX() const;
    const MitigationReport isIsolation() const;
    const MitigationReport isSEH() const;
    const MitigationReport isCFG() const;
#ifdef _WIN32
    const MitigationReport isAuthenticode() const;
#endif
    const MitigationReport isRFG() const;
    const MitigationReport isSafeSEH() const;
    const MitigationReport isGS() const;
    const MitigationReport isDotNET() const;

    operator json() const;
    friend std::ostream& operator<<(std::ostream& os, Checksec&);

   private:
    std::string filepath_;
    std::uint16_t imageCharacteristics_ = 0;
    std::uint16_t dllCharacteristics_ = 0;
    std::uint32_t loadConfigSize_ = 0;
    std::uint32_t loadConfigGuardFlags_ = 0;
    std::uint64_t loadConfigSEHandlerTable_ = 0;
    std::uint64_t loadConfigSEHandlerCount_ = 0;
    std::uint64_t loadConfigSecurityCookie_ = 0;
    peparse::data_directory clrConfig_ = {0};
};

}  // namespace checksec
