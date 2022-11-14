#include "checksec.h"
#include "vendor/argh.h"
#include "vendor/json.hpp"

using json = nlohmann::json;

namespace checksec {
void to_json(json& j, const MitigationPresence& p) {
    switch (p) {
        default: {
            j = "Unknown";
            break;
        }
        case MitigationPresence::Present: {
            j = "Present";
            break;
        }
        case MitigationPresence::NotPresent: {
            j = "NotPresent";
            break;
        }
        case MitigationPresence::NotApplicable: {
            j = "NotApplicable";
            break;
        }
        case MitigationPresence::NotImplemented: {
            j = "NotImplemented";
            break;
        }
    }
}

void to_json(json& j, const MitigationReport& r) {
    j = {
        {"presence", r.presence},
        {"description", r.description},
    };

    if (r.explanation) {
        j["explanation"] = r.explanation.value();
    }
}

void to_json(json& j, const Checksec& c) {
    j = {
        {
            "mitigations",
            {
                {"dynamicBase", c.isDynamicBase()},
                {"aslr", c.isASLR()},
                {"highEntropyVA", c.isHighEntropyVA()},
                {"forceIntegrity", c.isForceIntegrity()},
                {"isolation", c.isIsolation()},
                {"nx", c.isNX()},
                {"seh", c.isSEH()},
                {"cfg", c.isCFG()},
                {"rfg", c.isRFG()},
                {"safeSEH", c.isSafeSEH()},
                {"gs", c.isGS()},
                {"authenticode", c.isAuthenticode()},
                {"dotNET", c.isDotNET()},
                {"CetCompat", c.isCetCompat()},
            },
        },
        {"path", c.filepath()},
    };
}

std::ostream& operator<<(std::ostream& os, Checksec& self) {
    json j(self);
    os << "Dynamic Base    : " << j["mitigations"]["dynamicBase"]["presence"] << "\n";
    os << "ASLR            : " << j["mitigations"]["aslr"]["presence"] << "\n";
    os << "High Entropy VA : " << j["mitigations"]["highEntropyVA"]["presence"] << "\n";
    os << "Force Integrity : " << j["mitigations"]["forceIntegrity"]["presence"] << "\n";
    os << "Isolation       : " << j["mitigations"]["isolation"]["presence"] << "\n";
    os << "NX              : " << j["mitigations"]["nx"]["presence"] << "\n";
    os << "SEH             : " << j["mitigations"]["seh"]["presence"] << "\n";
    os << "CFG             : " << j["mitigations"]["cfg"]["presence"] << "\n";
    os << "RFG             : " << j["mitigations"]["rfg"]["presence"] << "\n";
    os << "SafeSEH         : " << j["mitigations"]["safeSEH"]["presence"] << "\n";
    os << "GS              : " << j["mitigations"]["gs"]["presence"] << "\n";
    os << "Authenticode    : " << j["mitigations"]["authenticode"]["presence"] << "\n";
    os << ".NET            : " << j["mitigations"]["dotNET"]["presence"] << "\n";
    os << "CET Compatible  : " << j["mitigations"]["CetCompat"]["presence"] << "\n";
    return os;
}
}  // namespace checksec

void usage(char* argv[]) {
    std::cerr << "Syntax : " << argv[0] << " [--json] <file [file ...]>"
              << "\n";
    std::cerr << "Example: " << argv[0] << " --json doom2.exe"
              << "\n";
    std::cerr << "  -j/--json will output JSON to stdout"
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
                results.push_back(csec);
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
