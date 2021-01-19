#include "checksec.h"
#include "vendor/argh.h"

using namespace std;

void usage(char* argv[]) {
    std::cerr << "Syntax : " << argv[0] << " [-j] <dll|exe>"
              << "\n";
    std::cerr << "Example: " << argv[0] << " -j doom2.exe"
              << "\n";
    std::cerr << "  -j will output json to stdout "
              << "\n";
}

void version() { std::cerr << "Winchecksec version " << WINCHECKSEC_VERSION << "\n"; }

int main(int argc, char* argv[]) {
    argh::parser cmdl(argc, argv);

    if (cmdl[{"-V", "--version"}]) {
        version();
        return 0;
    }

    bool json = cmdl[{"-j", "--json"}];
    if (cmdl.size() < 2) {
        usage(argv);
        return 1;
    }

    // TODO(ww): https://github.com/adishavit/argh/issues/57
    auto results = json::array();
    for (auto path = std::next(cmdl.begin()); path != cmdl.end(); ++path) {
        try {
            checksec::Checksec csec(*path);

            if (json) {
                results.push_back(csec.toJson());
            } else {
                std::cout << "Results for: " << *path << '\n';
                std::cout << csec << '\n';
            }
        } catch (checksec::ChecksecError& error) {
            std::cerr << error.what() << '\n';
            usage(argv);
            return 2;
        } catch (...) {
            std::cerr << "General error" << '\n';
            usage(argv);
            return 3;
        }
    }

    if (json) {
        std::cout << results << '\n';
    }

    return 0;
}
