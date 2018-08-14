#include "Checksec.h"
#include <windows.h>
#include <winnt.h>
#include <ostream>

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

    dllCharacteristics_ = imageOptionalHeader.DllCharacteristics;

}


json Checksec::toJson()     const  {
    return this->operator json();
}

Checksec::operator json() const {
    return json {
        { "dynamicBase",    isDynamicBase() },
        { "forceIntegrity", isForceIntegrity() },
        { "isolation",      isIsolation() },
        { "nx",             isNX() },
        { "seh",            isSEH() },
        { "path",           filepath_ },
    };
}

const bool Checksec::isDynamicBase()      const  {
    return dllCharacteristics_ & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
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


ostream& operator<<( ostream& os, Checksec& self ) {
    json j = self.operator json();
    os << "Dyanmic Base   : " << j["dynamicBase"] << endl;
    os << "Force Integrity: " << j["forceIntegrity"] << endl;
    os << "Isolation      : " << j["isolation"] << endl;
    os << "NX             : " << j["nx"] << endl;
    os << "SEH            : " << j["seh"] << endl;
    return os;
}

} // namespace
