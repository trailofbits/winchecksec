#include "Checksec.h"

#include <parser-library/parse.h>

#include <ostream>
#include <vector>
#include <optional>

#include "vendor/json.hpp"
using json = nlohmann::json;

namespace checksec {

void to_json(json& j, const MitigationPresence& p) {
    switch (p) {
        default: {
            j = "Unknown";
            break;
        }
        case MitigationPresence::Present: {
            j = "Present";
            break;
        }
        case MitigationPresence::NotPresent: {
            j = "NotPresent";
            break;
        }
        case MitigationPresence::NotApplicable: {
            j = "NotApplicable";
            break;
        }
        case MitigationPresence::NotImplemented: {
            j = "NotImplemented";
            break;
        }
    }
}

void to_json(json& j, const MitigationReport& r) {
    j = {
        {"presence", r.presence},
        {"description", r.description},
    };

    if (r.explanation) {
        j["explanation"] = r.explanation.value();
    }
}

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

    peparse::parsed_pe* operator&() { return pe_; }

   private:
    peparse::parsed_pe* pe_;
};

Checksec::Checksec(std::string filepath) : filepath_(filepath) {
    LoadedImage loadedImage{filepath};

    peparse::nt_header_32 nt = (&loadedImage)->peHeader.nt;
    peparse::file_header* imageFileHeader = &(nt.FileHeader);

    imageCharacteristics_ = imageFileHeader->Characteristics;
    std::vector<std::uint8_t> loadConfigData;

    // Check whether we need a 32 or 32+ optional header.
    if (nt.OptionalMagic == peparse::NT_OPTIONAL_64_MAGIC) {
        peparse::optional_header_64* optionalHeader = &(nt.OptionalHeader64);
        dllCharacteristics_ = optionalHeader->DllCharacteristics;
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_COM_DESCRIPTOR + 1) {
            std::cerr
                << "Warn: short image data directory vector (no CLR info?)"
                << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];

        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_LOAD_CONFIG + 1) {
            std::cerr
                << "Warn: short image data directory vector (no load config?)"
                << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(
                (&loadedImage), peparse::DIR_LOAD_CONFIG, loadConfigData)) {
            std::cerr << "Warn: No load config in the PE"
                      << "\n";
            return;
        }
        peparse::image_load_config_64 loadConfig;
        if (loadConfigData.size() > sizeof(loadConfig)) {
            std::cerr
                << "Warn: large load config, probably contains undocumented "
                   "fields"
                << "\n";
        }
        memcpy(&loadConfig, loadConfigData.data(), sizeof(loadConfig));
        loadConfigSize_ = loadConfig.Size;
        loadConfigGuardFlags_ = loadConfig.GuardFlags;
        loadConfigSecurityCookie_ = loadConfig.SecurityCookie;
        loadConfigSEHandlerTable_ = loadConfig.SEHandlerTable;
        loadConfigSEHandlerCount_ = loadConfig.SEHandlerCount;
    } else {
        peparse::optional_header_32* optionalHeader = &(nt.OptionalHeader);
        dllCharacteristics_ = optionalHeader->DllCharacteristics;
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_COM_DESCRIPTOR + 1) {
            std::cerr
                << "Warn: short image data directory vector (no CLR info?)"
                << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];
        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_LOAD_CONFIG + 1) {
            std::cerr
                << "Warn: short image data directory vector (no load config?)"
                << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(
                (&loadedImage), peparse::DIR_LOAD_CONFIG, loadConfigData)) {
            std::cerr << "Warn: No load config in the PE"
                      << "\n";
            return;
        }
        peparse::image_load_config_32 loadConfig;
        if (loadConfigData.size() > sizeof(loadConfig)) {
            std::cerr
                << "Warn: large load config, probably contains undocumented "
                   "fields"
                << "\n";
        }
        memcpy(&loadConfig, loadConfigData.data(), sizeof(loadConfig));
        loadConfigSize_ = loadConfig.Size;
        loadConfigGuardFlags_ = loadConfig.GuardFlags;
        loadConfigSecurityCookie_ = loadConfig.SecurityCookie;
        loadConfigSEHandlerTable_ = loadConfig.SEHandlerTable;
        loadConfigSEHandlerCount_ = loadConfig.SEHandlerCount;
    }
}

json Checksec::toJson() const { return this->operator json(); }

Checksec::operator json() const {
    return json{
        {
            "mitigations",
            {
                {"dynamicBase", isDynamicBase()},
                {"aslr", isASLR()},
                {"highEntropyVA", isHighEntropyVA()},
                {"forceIntegrity", isForceIntegrity()},
                {"isolation", isIsolation()},
                {"nx", isNX()},
                {"seh", isSEH()},
                {"cfg", isCFG()},
                {"rfg", isRFG()},
                {"safeSEH", isSafeSEH()},
                {"gs", isGS()},
#if _WIN32
                {"authenticode", isAuthenticode()},
#endif
                {"dotNET", isDotNET()},
            },
        },
        {"path", filepath_},
    };
}

const MitigationReport Checksec::isDynamicBase() const {
    if (dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        return REPORT(Present, kDynamicBaseDescription);
    } else {
        return REPORT(NotPresent, kDynamicBaseDescription);
    }
}

const MitigationReport Checksec::isASLR() const {
    // A binary is ASLR'd if:
    // * It was linked with /DYNAMICBASE and has *not* had its relocation
    // entries stripped, or
    // * It's managed by the CLR, which is always ASLR'd.
    if (isDynamicBase()) {
        if (imageCharacteristics_ & peparse::IMAGE_FILE_RELOCS_STRIPPED) {
            return REPORT_EXPLAIN(
                NotPresent, kASLRDescription,
                "Image has stripped relocations, making ASLR impossible.");
        }
        return REPORT(Present, kASLRDescription);
    } else if (isDotNET()) {
        return REPORT_EXPLAIN(Present, kASLRDescription,
                              ".NET binaries have ASLR via the .NET runtime.");
    } else {
        return REPORT(NotPresent, kASLRDescription);
    }
}

const MitigationReport Checksec::isHighEntropyVA() const {
    // NOTE(ww): Set by /HIGHENTROPYVA, but not exposed anywhere as a constant.
    // Only relevant on 64-bit machines with 64-bit images.
    // NOTE(ww): Additionally, don't count a binary as high-entropy capable
    // if it isn't also ASLR'd.
    if ((dllCharacteristics_ &
         peparse::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
        isASLR()) {
        return REPORT(Present, kHighEntropyVADescription);
    } else {
        return REPORT(NotPresent, kHighEntropyVADescription);
    }
}

const MitigationReport Checksec::isForceIntegrity() const {
    if (dllCharacteristics_ &
        peparse::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        return REPORT(Present, kForceIntegrityDescription);
    } else {
        return REPORT(NotPresent, kForceIntegrityDescription);
    }
}

const MitigationReport Checksec::isNX() const {
    if ((dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
        return REPORT(Present, kNXDescription);
    } else if (isDotNET()) {
        return REPORT_EXPLAIN(Present, kNXDescription,
                              ".NET binaries have DEP via the .NET runtime.");
    } else {
        return REPORT(NotPresent, kNXDescription);
    }
}

const MitigationReport Checksec::isIsolation() const {
    if (!(dllCharacteristics_ &
          peparse::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)) {
        return REPORT(Present, kIsolationDescription);
    } else {
        return REPORT(NotPresent, kIsolationDescription);
    }
}

const MitigationReport Checksec::isSEH() const {
    if (!(dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NO_SEH)) {
        return REPORT(Present, kSEHDescription);
    } else {
        return REPORT(NotPresent, kSEHDescription);
    }
}

const MitigationReport Checksec::isCFG() const {
    if (dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        return REPORT(Present, kCFGDescription);
    } else {
        return REPORT(NotPresent, kCFGDescription);
    }
}

const MitigationReport Checksec::isRFG() const {
    // NOTE(ww): a load config under 148 bytes implies the absence of the
    // GuardFlags field.
    if (loadConfigSize_ < 148) {
        return REPORT_EXPLAIN(NotPresent, kRFGDescription,
                              "Image load config is too short to contain RFG "
                              "configuration fields.");
    }

    // https://xlab.tencent.com/en/2016/11/02/return-flow-guard/
    if ((loadConfigGuardFlags_ & 0x00020000) &&
        (loadConfigGuardFlags_ & 0x00040000 ||
         loadConfigGuardFlags_ & 0x00080000)) {
        return REPORT(Present, kRFGDescription);
    } else {
        return REPORT(NotPresent, kRFGDescription);
    }
}

const MitigationReport Checksec::isSafeSEH() const {
    // NOTE(ww): a load config under 112 bytes implies the absence of the
    // SafeSEH fields.
    if (loadConfigSize_ < 112) {
        return REPORT_EXPLAIN(
            NotPresent, kSafeSEHDescription,
            "Image load config is too short to contain a SE handler table.");
    }

    if (isSEH() && loadConfigSEHandlerTable_ != 0 &&
        loadConfigSEHandlerCount_ != 0) {
        return REPORT(Present, kSafeSEHDescription);
    } else {
        return REPORT(NotPresent, kSafeSEHDescription);
    }
}

const MitigationReport Checksec::isGS() const {
    // NOTE(ww): a load config under 96 bytes implies the absence of the
    // SecurityCookie field.
    if (loadConfigSize_ < 96) {
        return REPORT_EXPLAIN(
            NotPresent, kGSDescription,
            "Image load config is too short to contain a GS security cookie.");
    }

    if (loadConfigSecurityCookie_ != 0) {
        return REPORT(Present, kGSDescription);
    } else {
        return REPORT(NotPresent, kGSDescription);
    }
}

const MitigationReport Checksec::isDotNET() const {
    if (clrConfig_.VirtualAddress != 0) {
        return REPORT(Present, kDotNETDescription);
    } else {
        return REPORT(NotPresent, kDotNETDescription);
    }
}

std::ostream& operator<<(std::ostream& os, Checksec& self) {
    json j = self.operator json();
    os << "Dynamic Base    : " << j["mitigations"]["dynamicBase"]["presence"]
       << "\n";
    os << "ASLR            : " << j["mitigations"]["aslr"]["presence"] << "\n";
    os << "High Entropy VA : " << j["mitigations"]["highEntropyVA"]["presence"]
       << "\n";
    os << "Force Integrity : " << j["mitigations"]["forceIntegrity"]["presence"]
       << "\n";
    os << "Isolation       : " << j["mitigations"]["isolation"]["presence"]
       << "\n";
    os << "NX              : " << j["mitigations"]["nx"]["presence"] << "\n";
    os << "SEH             : " << j["mitigations"]["seh"]["presence"] << "\n";
    os << "CFG             : " << j["mitigations"]["cfg"]["presence"] << "\n";
    os << "RFG             : " << j["mitigations"]["rfg"]["presence"] << "\n";
    os << "SafeSEH         : " << j["mitigations"]["safeSEH"]["presence"]
       << "\n";
    os << "GS              : " << j["mitigations"]["gs"]["presence"] << "\n";
#ifdef _WIN32
    os << "Authenticode    : " << j["mitigations"]["authenticode"]["presence"]
       << "\n";
#endif
    os << ".NET            : " << j["mitigations"]["dotNET"]["presence"]
       << "\n";
    return os;
}

}  // namespace checksec
