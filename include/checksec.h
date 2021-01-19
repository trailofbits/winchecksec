#pragma once

#include <iostream>
#include <string>
#include <optional>

#include <parser-library/parse.h>

namespace checksec {

/**
 * Raised on Checksec instantiation in the event of malformed or invalid PE.
 */
class ChecksecError : public std::runtime_error {
   public:
    ChecksecError(const char* what) : std::runtime_error(what) {}
};

/**
 * A namespace for winchecksec's implementation internals.
 *
 * Members of this namespace are not part of the public API.
 */
namespace impl {
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

/**
 * A RAII wrapped for `pe-parse::parsed_pe`.
 */
class LoadedImage {
   public:
    explicit LoadedImage(const std::string path) {
        if (!(pe_ = peparse::ParsePEFromFile(path.c_str()))) {
            throw ChecksecError("Couldn't load file; corrupt or not a PE?");
        }
    }
    ~LoadedImage() { peparse::DestructParsedPE(pe_); }

    // can't make copies of LoadedImage
    LoadedImage(const LoadedImage&) = delete;
    LoadedImage& operator=(const LoadedImage&) = delete;

    peparse::parsed_pe* get() const { return pe_; }

   private:
    peparse::parsed_pe* pe_;
};
}  // namespace impl

/**
 * Models the state of a security mitigation.
 *
 * Every mitigation supported by winchecksec is in one of these states.
 */
enum class MitigationPresence {
    Present,        /**< The mitigation is present */
    NotPresent,     /**< The mitigation is not present */
    NotApplicable,  /**< The mitigation is not applicable on this input */
    NotImplemented, /**< Support for detecting this mitigation is not implemented */
};

/**
 * Represents a "report" on a particular security mitigation.
 */
struct MitigationReport {
    /**
     * A MitigationPresence indicating the mitigation's state.
     */
    MitigationPresence presence;

    /**
     * A brief description of the mitigation.
     */
    std::string description;

    /**
     * An optional explanation of the mitigation's detection (or non-detection).
     */
    std::optional<std::string> explanation;

    /**
     * @return true if `presence` is \ref MitigationPresence::Present, false otherwise
     */
    operator bool() const { return presence == MitigationPresence::Present; }
};

/**
 * Represents the main winchecksec interface.
 */
class Checksec {
   public:
    Checksec(std::string filepath);

    /**
     * @return a string reference for the filepath that this `Checksec` instance was created with
     */
    const std::string filepath() const { return filepath_; }

    /**
     * @return a MitigationReport indicating whether the program can be loaded from a dynamic base
     *  address (i.e. `/DYNAMICBASE`)
     */
    const MitigationReport isDynamicBase() const;

    /**
     * @return a MitigationReport indicating whether the program has **effective** ASLR
     *  (i.e., has a dynamic base and unstripped relocations, or is in a managed runtime like .NET)
     */
    const MitigationReport isASLR() const;

    /**
     * @return a MitigationReport indicating whether the program supports 64-bit ASLR
     */
    const MitigationReport isHighEntropyVA() const;

    /**
     * @return a MitigationReport indicating whether the program's integrity
     *  must be checked at load time
     */
    const MitigationReport isForceIntegrity() const;

    /**
     * @return a MitigationReport indicating whether the program supports
     *  NX, (a.k.a. DEP, `W^X`)
     */
    const MitigationReport isNX() const;

    /**
     * @return a MitigationReport indicating whether the operating system
     *  should attempt a manifest lookup and load for the program
     */
    const MitigationReport isIsolation() const;

    /**
     * @return a MitigationReport indicating whether the program uses Structured Exception Handlers
     */
    const MitigationReport isSEH() const;

    /**
     * @return a MitigationReport indicating whether the program supports Control Flow Guard
     */
    const MitigationReport isCFG() const;

    /**
     * @return a MitigationReport indicating whether the program contains a (partially) valid
     *  Authenticode signature
     *
     * @note See the [`uthenticode`](https://trailofbits.github.io/uthenticode/index.html)
     *       documentation for the details of this check
     */
    const MitigationReport isAuthenticode() const;

    /**
     * @return a MitigationReport indicating whether the program supports Return Flow Guard
     */
    const MitigationReport isRFG() const;

    /**
     * @return a MitigationReport indicating whether the program supports safe SEH
     */
    const MitigationReport isSafeSEH() const;

    /**
     * @return a MitigationReport indicating whether the program uses stack buffer cookies
     *  (a.k.a. stack guards, stack canaries)
     *
     * @note This check tests for the presence of the security cookie's address and **not**
     *       the instrumentation that actually checks that address. Every modern version of
     *       MSVCRT has stack cookies enabled in some form, so this can result in false
     *       positives if your application code links to MSVCRT but doesn't enable its own
     *       stack cookies.
     */
    const MitigationReport isGS() const;

    /**
     * @return a MitigationReport indicating whether this program runs in the .NET environment
     */
    const MitigationReport isDotNET() const;

   private:
    impl::LoadedImage loadedImage_;
    std::string filepath_;
    std::uint16_t targetMachine_ = 0;
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
