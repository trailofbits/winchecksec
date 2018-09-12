#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
#include <softpub.h>
#include <imagehlp.h>

#include <ostream>
#include <codecvt>

#include "Checksec.h"

using namespace std;

#include "json.hpp"
using json = nlohmann::json;

namespace checksec {

Checksec::Checksec(string filepath)
: filepath_(filepath)
{
    LOADED_IMAGE loadedImage = {0};

    if (!MapAndLoad(filepath_.c_str(), NULL, &loadedImage, true, true)) {
        throw ChecksecError("Couldn't load file; corrupt or not a PE?");
    }

    IMAGE_FILE_HEADER imageFileHeader = loadedImage.FileHeader->FileHeader;
    IMAGE_OPTIONAL_HEADER imageOptionalHeader = loadedImage.FileHeader->OptionalHeader;

    imageCharacteristics_ = imageFileHeader.Characteristics;
    dllCharacteristics_ = imageOptionalHeader.DllCharacteristics;

    // Warn and return early if the image data directory vector
    // is too short to contain a reference to the IMAGE_LOAD_CONFIG_DIRECTORY.
    if (imageOptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1) {
        cerr << "Warn: short image data directory vector" << "\n";
        goto end;
    }

    // https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_data_directory
    IMAGE_DATA_DIRECTORY dir = imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    if (!dir.VirtualAddress || !dir.Size) {
        cerr << "Warn: No IMAGE_LOAD_CONFIG_DIRECTORY in the PE" << "\n";
        goto end;
    }

    // NOTE(ww): This always returns false, even when there definitely is an
    // IMAGE_LOAD_CONFIG_DIRECTORY in the image. Microsoft never bothered
    // to update the internal size check, and still compares it against 0x40
    // (the Windows XP load config size).
    // loadConfig_.Size = sizeof(dir.Size);
    // if (!GetImageConfigInformation(&loadedImage, &loadConfig_)) {
    //     cerr << "Warn: Couldn't retrieve IMAGE_LOAD_CONFIG_DIRECTORY: " << GetLastError() << "\n";
    // }

    IMAGE_SECTION_HEADER sectionHeader = {0};

    // Find the section that contains the load config directory.
    // This should always be .rdata, but who knows?
    // TODO(ww): We should be able to use ImageDirectoryEntryToDataEx here.
    for (uint64_t i = 0; i < loadedImage.NumberOfSections; i++) {
        if (loadedImage.Sections[i].VirtualAddress < dir.VirtualAddress
            && loadedImage.Sections[i].VirtualAddress > sectionHeader.VirtualAddress)
        {
            sectionHeader = loadedImage.Sections[i];
        }
    }

    size_t loadConfigOffset = dir.VirtualAddress
                              - sectionHeader.VirtualAddress
                              + sectionHeader.PointerToRawData;

    size_t loadConfigSize = (dir.Size < sizeof(loadConfig_)) ? dir.Size : sizeof(loadConfig_);
    DWORD txsize = 0;

    // TODO(ww): MapAndLoad maps the image into memory, so we could probably just
    // `memcpy` from `loadedImage.MappedAddress + loadConfigOffset` here.
    SetFilePointer(loadedImage.hFile, (LONG) loadConfigOffset, NULL, FILE_BEGIN);
    ReadFile(loadedImage.hFile, &loadConfig_, (DWORD) loadConfigSize, &txsize, NULL);

    if (txsize != loadConfigSize) {
        throw ChecksecError("Short read of load config from file (I/O error?)");
    }

    end:
    UnMapAndLoad(&loadedImage);
}

json Checksec::toJson() const
{
    return this->operator json();
}

Checksec::operator json() const
{
    return json {
        { "dynamicBase",    isDynamicBase() },
        { "aslr",           isASLR() },
        { "highEntropyVA",  isHighEntropyVA() },
        { "forceIntegrity", isForceIntegrity() },
        { "isolation",      isIsolation() },
        { "nx",             isNX() },
        { "seh",            isSEH() },
        { "cfg",            isCFG() },
        { "rfg",            isRFG() },
        { "safeSEH",        isSafeSEH() },
        { "gs",             isGS() },
        { "authenticode",   isAuthenticode() },
        { "path",           filepath_ },
    };
}

const bool Checksec::isDynamicBase() const
{
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

const bool Checksec::isASLR() const
{
    return !(imageCharacteristics_ & IMAGE_FILE_RELOCS_STRIPPED) && isDynamicBase();
}

const bool Checksec::isHighEntropyVA() const
{
    // NOTE(ww): Set by /HIGHENTROPYVA, but not exposed anywhere as a constant.
    // Only relevant on 64-bit machines with 64-bit images.
    return dllCharacteristics_ & 0x20;
}

const bool Checksec::isForceIntegrity() const
{
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
}

const bool Checksec::isNX() const
{
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
}

const bool Checksec::isIsolation() const
{
    return !(dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
}

const bool Checksec::isSEH() const
{
    return !(dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NO_SEH);
}

const bool Checksec::isCFG() const
{
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_GUARD_CF;
}

const bool Checksec::isAuthenticode() const
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring filePathW = converter.from_bytes(filepath_);

    WINTRUST_FILE_INFO fileInfo = {
        sizeof(fileInfo),    /* cbStruct */
        filePathW.c_str(),   /* pcwszFilePath */
        NULL,                /* hFile */
        NULL,                /* pgKnownSubject */
    };

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {
        sizeof(trustData),        /* cbStruct */
        NULL,                     /* pPolicyCallbackData */
        NULL,                     /* pSIPClientData */
        WTD_UI_NONE,              /* dwUIChoice */
        WTD_REVOKE_NONE,          /* fdwRevocationChecks */
        WTD_CHOICE_FILE,          /* dwUnionChoice */
        &fileInfo,                /* pFile */
        WTD_STATEACTION_VERIFY,   /* dwStateAction */
        NULL,                     /* hWVTStateData */
        NULL,                     /* pwszURLReference */
        0,                        /* dwProvFlags */
        0,                        /* dwUIContext */
        NULL,                     /* pSignatureSettings */
    };

    uint32_t status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}

const bool Checksec::isRFG() const
{
    // NOTE(ww): a load config under 148 bytes implies the absence of the GuardFlags field.
    if (loadConfig_.Size < 148) {
        cerr << "Warn: no or short load config, assuming no RFG" << "\n";
        return false;
    }

    // https://xlab.tencent.com/en/2016/11/02/return-flow-guard/
    return (loadConfig_.GuardFlags & 0x00020000)
        && (loadConfig_.GuardFlags & 0x00040000 || loadConfig_.GuardFlags & 0x00080000);
}

const bool Checksec::isSafeSEH() const
{
    // NOTE(ww): a load config under 112 bytes implies the absence of the SafeSEH fields.
    if (loadConfig_.Size < 112) {
        cerr << "Warn: no or short load config, assuming no SafeSEH" << "\n";
        return false;
    }

    return isSEH() && loadConfig_.SEHandlerTable != 0 && loadConfig_.SEHandlerCount != 0;
}

const bool Checksec::isGS() const
{
    // NOTE(ww): a load config under 96 bytes implies the absence of the SecurityCookie field.
    if (loadConfig_.Size < 96) {
        cerr << "Warn: no or short load config, assuming no GS" << "\n";
        return false;
    }

    // TODO(ww): Handle the edge case where the user defines a custom entry point
    // and fails to call __security_init_cookie().
    return loadConfig_.SecurityCookie != 0;
}

ostream& operator<<(ostream& os, Checksec& self)
{
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
    os << "Authenticode    : " << j["authenticode"] << "\n";
    return os;
}

} // namespace
