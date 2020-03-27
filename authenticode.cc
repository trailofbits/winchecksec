#include "Checksec.h"

#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <winnt.h>

#include <codecvt>

const bool Checksec::isAuthenticode() const {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring filePathW = converter.from_bytes(filepath_);

    WINTRUST_FILE_INFO fileInfo = {
        sizeof(fileInfo),  /* cbStruct */
        filePathW.c_str(), /* pcwszFilePath */
        NULL,              /* hFile */
        NULL,              /* pgKnownSubject */
    };

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {
        sizeof(trustData),      /* cbStruct */
        NULL,                   /* pPolicyCallbackData */
        NULL,                   /* pSIPClientData */
        WTD_UI_NONE,            /* dwUIChoice */
        WTD_REVOKE_NONE,        /* fdwRevocationChecks */
        WTD_CHOICE_FILE,        /* dwUnionChoice */
        &fileInfo,              /* pFile */
        WTD_STATEACTION_VERIFY, /* dwStateAction */
        NULL,                   /* hWVTStateData */
        NULL,                   /* pwszURLReference */
        0,                      /* dwProvFlags */
        0,                      /* dwUIContext */
        NULL,                   /* pSignatureSettings */
    };

    uint32_t status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}
