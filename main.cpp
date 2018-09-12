#include "Checksec.h"

using namespace std;

void usage(char* argv[])
{
    cerr << "Syntax : " << argv[0] << " [-j] <dll|exe>" << endl;
    cerr << "Example: " << argv[0] << " -j doom2.exe" << endl;
    cerr << "  -j will output json to stdout " << endl;
}

int main(int argc, char* argv[])
{
    if (argc != 2 && argc != 3) {
        cerr << argc << endl;
        usage(argv);
        return -__LINE__;
    }

    bool jsonOutput = false;
    string path;

    switch (argc) {
        case 2:
            path = argv[1];
            break;
        case 3:
            jsonOutput = ("-j" == string(argv[1]));
            path = argv[2];
            break;
        default:
            usage(argv);
            return -__LINE__;
    }


    try {
        checksec::Checksec csec = path;

        if (jsonOutput) {
            cout << csec.toJson() << endl;
        } else {
            cout << csec << endl;
        }
    } catch (const char *x1) {
        cerr << x1 << endl;
        usage(argv);
        return -__LINE__;
    } catch (...) {
        cerr << "General error" << endl;
        usage(argv);
        return -__LINE__;
    }

    return 0;
}
