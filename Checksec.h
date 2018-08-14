#ifndef CHECKSEC_H
#define CHECKSEC_H

#include <string>
#include <iostream>
#include <fstream>
#include "vendor/json.hpp"
using json = nlohmann::json;


using namespace std;

namespace sl2 {

class Checksec  {
public:
    Checksec( string filepath ) :
            filepath_(filepath),
            filestream_( filepath_, ios::binary ) {

        if( !filestream_.is_open() ) {
            string msg = "Unable to open " + filepath;
            cerr << msg << endl;
            throw msg;
        }

        process();

    }



    json toJson() const;

    const bool isDynamicBase()      const;
    const bool isForceIntegrity()   const;
    const bool isNX()               const;
    const bool isIsolation()        const;
    const bool isSEH()              const;

    operator json() const;
    friend ostream& operator<<( ostream& os, Checksec& );


private:

    void                process();
    string              filepath_;
    ifstream            filestream_;
    uint16_t            dllCharacteristics_ = 0;
};

} // namespace
#endif