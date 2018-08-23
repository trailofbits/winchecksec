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
    return os;
}

} // namespace
