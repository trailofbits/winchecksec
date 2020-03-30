#include "Checksec.h"

#include <parser-library/parse.h>

#include <ostream>
#include <vector>

using namespace std;

#include "vendor/json.hpp"
using json = nlohmann::json;

namespace checksec {

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

Checksec::Checksec(string filepath) : filepath_(filepath) {
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
            cerr << "Warn: short image data directory vector (no CLR info?)"
                 << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];

        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_LOAD_CONFIG + 1) {
            cerr << "Warn: short image data directory vector (no load config?)"
                 << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(
                (&loadedImage), peparse::DIR_LOAD_CONFIG, loadConfigData)) {
            cerr << "Warn: No load config in the PE"
                 << "\n";
            return;
        }
        peparse::image_load_config_64 loadConfig;
        if (loadConfigData.size() > sizeof(loadConfig)) {
            cerr << "Warn: large load config, probably contains undocumented "
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
            cerr << "Warn: short image data directory vector (no CLR info?)"
                 << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];
        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes <
            peparse::DIR_LOAD_CONFIG + 1) {
            cerr << "Warn: short image data directory vector (no load config?)"
                 << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(
                (&loadedImage), peparse::DIR_LOAD_CONFIG, loadConfigData)) {
            cerr << "Warn: No load config in the PE"
                 << "\n";
            return;
        }
        peparse::image_load_config_32 loadConfig;
        if (loadConfigData.size() > sizeof(loadConfig)) {
            cerr << "Warn: large load config, probably contains undocumented "
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
    return json {
        {"dynamicBase", isDynamicBase()}, {"aslr", isASLR()},
            {"highEntropyVA", isHighEntropyVA()},
            {"forceIntegrity", isForceIntegrity()},
            {"isolation", isIsolation()}, {"nx", isNX()}, {"seh", isSEH()},
            {"cfg", isCFG()}, {"rfg", isRFG()}, {"safeSEH", isSafeSEH()},
            {"gs", isGS()},
#if _WIN32
            {"authenticode", isAuthenticode()},
#endif
            {"dotNET", isDotNET()}, {"path", filepath_},
    };
}

const bool Checksec::isDynamicBase() const {
    return !!(dllCharacteristics_ &
              peparse::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
}

const bool Checksec::isASLR() const {
    // A binary is ASLR'd if:
    // * It was linked with /DYNAMICBASE and has *not* had its relocation
    // entries stripped, or
    // * It's managed by the CLR, which is always ASLR'd.
    return (!(imageCharacteristics_ & peparse::IMAGE_FILE_RELOCS_STRIPPED) &&
            isDynamicBase()) ||
           isDotNET();
}

const bool Checksec::isHighEntropyVA() const {
    // NOTE(ww): Set by /HIGHENTROPYVA, but not exposed anywhere as a constant.
    // Only relevant on 64-bit machines with 64-bit images.
    // NOTE(ww): Additionally, don't count a binary as high-entropy capable
    // if it isn't also ASLR'd.
    return (dllCharacteristics_ &
            peparse::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
           isASLR();
}

const bool Checksec::isForceIntegrity() const {
    return !!(dllCharacteristics_ &
              peparse::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
}

const bool Checksec::isNX() const {
    return (dllCharacteristics_ &
            peparse::IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ||
           isDotNET();
}

const bool Checksec::isIsolation() const {
    return !(dllCharacteristics_ &
             peparse::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
}

const bool Checksec::isSEH() const {
    return !(dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NO_SEH);
}

const bool Checksec::isCFG() const {
    return !!(dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_GUARD_CF);
}

const bool Checksec::isRFG() const {
    // NOTE(ww): a load config under 148 bytes implies the absence of the
    // GuardFlags field.
    if (loadConfigSize_ < 148) {
        cerr << "Warn: no or short load config, assuming no RFG"
             << "\n";
        return false;
    }

    // https://xlab.tencent.com/en/2016/11/02/return-flow-guard/
    return (loadConfigGuardFlags_ & 0x00020000) &&
           (loadConfigGuardFlags_ & 0x00040000 ||
            loadConfigGuardFlags_ & 0x00080000);
}

const bool Checksec::isSafeSEH() const {
    // NOTE(ww): a load config under 112 bytes implies the absence of the
    // SafeSEH fields.
    if (loadConfigSize_ < 112) {
        cerr << "Warn: no or short load config, assuming no SafeSEH"
             << "\n";
        return false;
    }

    return isSEH() && loadConfigSEHandlerTable_ != 0 &&
           loadConfigSEHandlerCount_ != 0;
}

const bool Checksec::isGS() const {
    // NOTE(ww): a load config under 96 bytes implies the absence of the
    // SecurityCookie field.
    if (loadConfigSize_ < 96) {
        cerr << "Warn: no or short load config, assuming no GS"
             << "\n";
        return false;
    }

    return loadConfigSecurityCookie_ != 0;
}

const bool Checksec::isDotNET() const { return clrConfig_.VirtualAddress != 0; }

ostream& operator<<(ostream& os, Checksec& self) {
    json j = self.operator json();
    os << "Dynamic Base    : " << j["dynamicBase"] << "\n";
    os << "ASLR            : " << j["aslr"] << "\n";
    os << "High Entropy VA : " << j["highEntropyVA"] << "\n";
    os << "Force Integrity : " << j["forceIntegrity"] << "\n";
    os << "Isolation       : " << j["isolation"] << "\n";
    os << "NX              : " << j["nx"] << "\n";
    os << "SEH             : " << j["seh"] << "\n";
    os << "CFG             : " << j["cfg"] << "\n";
    os << "RFG             : " << j["rfg"] << "\n";
    os << "SafeSEH         : " << j["safeSEH"] << "\n";
    os << "GS              : " << j["gs"] << "\n";
#ifdef _WIN32
    os << "Authenticode    : " << j["authenticode"] << "\n";
#endif
    os << ".NET            : " << j["dotNET"] << "\n";
    return os;
}

}  // namespace checksec
