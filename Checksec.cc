#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
#include <softpub.h>

#include <ostream>
#include <codecvt>

#include "Checksec.h"

using namespace std;

#include "json.hpp"
using json = nlohmann::json;

namespace checksec {

void Checksec::process() {

    IMAGE_DOS_HEADER        imageDosHeader;
    IMAGE_FILE_HEADER       imageFileHeader;
    IMAGE_OPTIONAL_HEADER   imageOptionalHeader;
    uint32_t                imageDosHeaderExtra[16];
    uint32_t                ntSignature;



    filestream_.read( (char*)&imageDosHeader,       sizeof(imageDosHeader) );
    if( imageDosHeader.e_magic != IMAGE_DOS_SIGNATURE ) {
        string msg = "Not a valid DOS header.";
        throw msg;
    }

    filestream_.read( (char*)&imageDosHeaderExtra,  sizeof(imageDosHeaderExtra) );

    filestream_.seekg( imageDosHeader.e_lfanew, ios_base::beg );
    filestream_.read( (char*)&ntSignature,          sizeof(ntSignature) );
    if( ntSignature!= IMAGE_NT_SIGNATURE ) {
        string msg = "Not a valid NT Signature.";
        throw msg;
    }
    filestream_.read( (char*)&imageFileHeader,      sizeof(imageFileHeader) );
    filestream_.read( (char*)&imageOptionalHeader,  sizeof(imageOptionalHeader) );

    imageCharacteristics_ = imageFileHeader.Characteristics;
    dllCharacteristics_ = imageOptionalHeader.DllCharacteristics;

}


json Checksec::toJson()     const  {
    return this->operator json();
}

Checksec::operator json() const {
    return json {
        { "dynamicBase",    isDynamicBase() },
        { "aslr",           isASLR() },
        { "highEntropyVA",  isHighEntropyVA() },
        { "forceIntegrity", isForceIntegrity() },
        { "isolation",      isIsolation() },
        { "nx",             isNX() },
        { "seh",            isSEH() },
        { "cfg",            isCFG() },
        { "authenticode",   isAuthenticode() },
        { "path",           filepath_ },
    };
}

const bool Checksec::isDynamicBase()      const  {
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

const bool Checksec::isASLR()             const {
    return !(imageCharacteristics_ & IMAGE_FILE_RELOCS_STRIPPED) && isDynamicBase();
}

const bool Checksec::isHighEntropyVA()    const {
    // NOTE(ww): Set by /HIGHENTROPYVA, but not exposed anywhere as a constant.
    // Only relevant on 64-bit machines with 64-bit images.
    return dllCharacteristics_ & 0x20;
}

const bool Checksec::isForceIntegrity()   const {
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
}

const bool Checksec::isNX()               const {
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
}

const bool Checksec::isIsolation()        const {
    return !(dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
}

const bool Checksec::isSEH()              const {
    return !(dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_NO_SEH);
}

const bool Checksec::isCFG()              const {
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_GUARD_CF;
}

const bool Checksec::isAuthenticode()     const {
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

    // if (status == TRUST_E_SUBJECT_NOT_TRUSTED) {
    //     std::cout << "NOT TRUSTED" << std::endl;
    // }
    // else if (status == TRUST_E_PROVIDER_UNKNOWN) {
    //     std::cout << "PROVIDER UNKNOWN" << std::endl;
    // }
    // else if (status == TRUST_E_ACTION_UNKNOWN) {
    //     std::cout << "ACTION UNKNOWN" << std::endl;
    // }
    // else if (status == TRUST_E_SUBJECT_FORM_UNKNOWN) {
    //     std::cout << "SUBJECT FORM UNKNOWN" << std::endl;
    // }
    // else if (status == TRUST_E_NO_SIGNATURE) {
    //     std::cout << "NO SIGNATURE" << std::endl;
    // }
    // else if (status == TRUST_E_)
    // else if (status != ERROR_SUCCESS) {
    //     std::cout << "GLE=" << GetLastError() << std::endl;
    // }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}


ostream& operator<<( ostream& os, Checksec& self ) {
    json j = self.operator json();
    os << "Dyanmic Base    : " << j["dynamicBase"] << endl;
    os << "ASLR            : " << j["aslr"] << endl;
    os << "High Entropy VA : " << j["highEntropyVA"] << endl;
    os << "Force Integrity : " << j["forceIntegrity"] << endl;
    os << "Isolation       : " << j["isolation"] << endl;
    os << "NX              : " << j["nx"] << endl;
    os << "SEH             : " << j["seh"] << endl;
    os << "CFG             : " << j["cfg"] << endl;
    os << "Authenticode    : " << j["authenticode"] << endl;
    return os;
}

} // namespace
