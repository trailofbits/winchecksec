#include "Checksec.h"

using namespace std;

static string VERSION = "1.1.0";

void usage(char* argv[])
{
    cerr << "Syntax : " << argv[0] << " [-j] <dll|exe>" << "\n";
    cerr << "Example: " << argv[0] << " -j doom2.exe" << "\n";
    cerr << "  -j will output json to stdout " << "\n";
}

void version()
{
    cerr << "Winchecksec version " << VERSION << "\n";
}

int main(int argc, char* argv[])
{
    if (argc != 2 && argc != 3) {
        cerr << "Unexpected number of arguments" << "\n";
        usage(argv);
        return -__LINE__;
    }

    bool jsonOutput = false;
    string path;

    switch (argc) {
        case 2:
            if (string(argv[1]) == "-V") {
                version();
                return 0;
            }
            path = argv[1];
            break;
        case 3:
            if (string(argv[1]) == "-j") {
                jsonOutput = true;
                path = argv[2];
            }
            else {
                usage(argv);
                return -__LINE__;
            }
            break;
        default:
            usage(argv);
            return -__LINE__;
    }


    try {
        checksec::Checksec csec = path;

        if (jsonOutput) {
            cout << csec.toJson() << "\n";
        }
        else {
            cout << csec << "\n";
        }
    }
    catch (checksec::ChecksecError& error) {
        cerr << error.what() << "\n";
        usage(argv);
        return -__LINE__;
    }
    catch (...) {
        cerr << "General error" << "\n";
        usage(argv);
        return -__LINE__;
    }

    return 0;
}
