#include "Timer.h"
#include "KeyHunt.h"
#include "Base58.h"
#include "CmdParse.h"
#include <fstream>
#include <string>
#include <string.h>
#include <stdexcept>
#include <cassert>
#include <algorithm>
#ifndef WIN64
#include <signal.h>
#include <unistd.h>
#endif

#define RELEASE "1.07"

using namespace std;
bool should_exit = false;

// ----------------------------------------------------------------------------
void usage()
{
    printf("KeyHunt-Cuda [OPTIONS...] [TARGETS]\n");
    printf("Where TARGETS is one address/xpont, or multiple hashes/xpoints file\n\n");

    printf("-h, --help                               : Display this message\n");
    printf("-c, --check                              : Check the working of the codes\n");
    printf("-u, --uncomp                             : Search uncompressed points\n");
    printf("-b, --both                               : Search both uncompressed or compressed points\n");
    printf("-g, --gpu                                : Enable GPU calculation\n");
    printf("--gpui GPU ids: 0,1,...                  : List of GPU(s) to use, default is 0\n");
    printf("--gpux GPU gridsize: g0x,g0y,g1x,g1y,... : Specify GPU(s) kernel gridsize, default is 8*(Device MP count),128\n");
    printf("-t, --thread N                           : Specify number of CPU thread, default is number of core\n");
    printf("-i, --in FILE                            : Read rmd160 hashes or xpoints from FILE, should be in binary format with sorted\n");
    printf("-o, --out FILE                           : Write keys to FILE, default: Found.txt\n");
    printf("-m, --mode MODE                          : Specify search mode where MODE is\n");
    printf("                                               ADDRESS  : for single address\n");
    printf("                                               ADDRESSES: for multiple hashes/addresses\n");
    printf("                                               XPOINT   : for single xpoint\n");
    printf("                                               XPOINTS  : for multiple xpoints\n");
    printf("--coin BTC/ETH                           : Specify Coin name to search\n");
    printf("                                               BTC: available mode :-\n");
    printf("                                                   ADDRESS, ADDRESSES, XPOINT, XPOINTS\n");
    printf("                                               ETH: available mode :-\n");
    printf("                                                   ADDRESS, ADDRESSES\n");
    printf("-l, --list                               : List cuda enabled devices\n");
    printf("--range KEYSPACE                         : Specify the range:\n");
    printf("                                               START:END\n");
    printf("                                               START:+COUNT\n");
    printf("                                               START\n");
    printf("                                               :END\n");
    printf("                                               :+COUNT\n");
    printf("                                               Where START, END, COUNT are in hex format\n");
    printf("-r, --rkey Rkey                          : Random key interval in MegaKeys, default is disabled\n");
    printf("-v, --version                            : Show version\n");
}

// ----------------------------------------------------------------------------

void getInts(string name, vector<int>& tokens, const string& text, char sep)
{

    size_t start = 0, end = 0;
    tokens.clear();
    int item;

    try {

        while ((end = text.find(sep, start)) != string::npos) {
            item = std::stoi(text.substr(start, end - start));
            tokens.push_back(item);
            start = end + 1;
        }

        item = std::stoi(text.substr(start));
        tokens.push_back(item);

    }
    catch (std::invalid_argument&) {

        printf("Invalid %s argument, number expected\n", name.c_str());
        usage();
        exit(-1);

    }

}

// ----------------------------------------------------------------------------

int parseSearchMode(const std::string& s)
{
    std::string stype = s;
    std::transform(stype.begin(), stype.end(), stype.begin(), ::tolower);

    if (stype == "address") {
        return SEARCH_MODE_SA;
    }

    if (stype == "xpoint") {
        return SEARCH_MODE_SX;
    }

    if (stype == "addresses") {
        return SEARCH_MODE_MA;
    }

    if (stype == "xpoints") {
        return SEARCH_MODE_MX;
    }

    printf("Invalid search mode format: %s", stype.c_str());
    usage();
    exit(-1);
}

// ----------------------------------------------------------------------------

int parseCoinType(const std::string& s)
{
    std::string stype = s;
    std::transform(stype.begin(), stype.end(), stype.begin(), ::tolower);

    if (stype == "btc") {
        return COIN_BTC;
    }

    if (stype == "eth") {
        return COIN_ETH;
    }

    printf("Invalid coin name: %s", stype.c_str());
    usage();
    exit(-1);
}

// ----------------------------------------------------------------------------

bool parseRange(const std::string& s, Int& start, Int& end)
{
    size_t pos = s.find(':');

    if (pos == std::string::npos) {
        start.SetBase16(s.c_str());
        end.Set(&start);
        end.Add(0xFFFFFFFFFFFFULL);
    }
    else {
        std::string left = s.substr(0, pos);

        if (left.length() == 0) {
            start.SetInt32(1);
        }
        else {
            start.SetBase16(left.c_str());
        }

        std::string right = s.substr(pos + 1);

        if (right[0] == '+') {
            Int t;
            t.SetBase16(right.substr(1).c_str());
            end.Set(&start);
            end.Add(&t);
        }
        else {
            end.SetBase16(right.c_str());
        }
    }

    return true;
}

#ifdef WIN64
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
        //printf("\n\nCtrl-C event\n\n");
        should_exit = true;
        return TRUE;

    default:
        return TRUE;
    }
}
#else
void CtrlHandler(int signum) {
    printf("\n\nBYE\n");
    exit(signum);
}
#endif

int main(int argc, char** argv)
{
    // Global Init
    Timer::Init();
    rseed(Timer::getSeed32());

    bool gpuEnable = false;
    bool gpuAutoGrid = true;
    int compMode = SEARCH_COMPRESSED;
    vector<int> gpuId = { 0 };
    vector<int> gridSize;

    string outputFile = "Found.txt";

    string inputFile = "";    // for both multiple hash160s and x points
    string address = "";    // for single address mode
    string xpoint = "";        // for single x point mode

    std::vector<unsigned char> hashORxpoint;
    bool singleAddress = false;
    int nbCPUThread = Timer::getCoreNumber();

    bool tSpecified = false;
    bool useSSE = true;
    uint32_t maxFound = 1024 * 64;

    uint64_t rKey = 0;

    Int rangeStart;
    Int rangeEnd;
    rangeStart.SetInt32(0);
    rangeEnd.SetInt32(0);

    int searchMode = 0;
    int coinType = COIN_BTC;

    hashORxpoint.clear();

    // cmd args parsing
    CmdParse parser;
    parser.add("-h", "--help", false);
    parser.add("-c", "--check", false);
    parser.add("-l", "--list", false);
    parser.add("-u", "--uncomp", false);
    parser.add("-b", "--both", false);
    parser.add("-g", "--gpu", false);
    parser.add("", "--gpui", true);
    parser.add("", "--gpux", true);
    parser.add("-t", "--thread", true);
    parser.add("-i", "--in", true);
    parser.add("-o", "--out", true);
    parser.add("-m", "--mode", true);
    parser.add("", "--coin", true);
    parser.add("", "--range", true);
    parser.add("-r", "--rkey", true);
    parser.add("-v", "--version", false);

    if (argc == 1) {
        usage();
        return 0;
    }
    try {
        parser.parse(argc, argv);
    }
    catch (std::string err) {
        printf("Error: %s\n", err.c_str());
        usage();
        exit(-1);
    }
    std::vector<OptArg> args = parser.getArgs();

    for (unsigned int i = 0; i < args.size(); i++) {
        OptArg optArg = args[i];
        std::string opt = args[i].option;

        try {
            if (optArg.equals("-h", "--help")) {
                usage();
                return 0;
            }
            else if (optArg.equals("-c", "--check")) {
                printf("KeyHunt-Cuda v" RELEASE "\n\n");
                printf("\nChecking... Secp256K1\n\n");
                Secp256K1* secp = new Secp256K1();
                secp->Init();
                secp->Check();
                printf("\n\nChecking... Int\n\n");
                Int* K = new Int();
                K->SetBase16("3EF7CEF65557B61DC4FF2313D0049C584017659A32B002C105D04A19DA52CB47");
                K->Check();
                delete secp;
                delete K;
                printf("\n\nChecked successfully\n\n");
                return 0;
            }
            else if (optArg.equals("-l", "--list")) {
#ifdef WIN64
                GPUEngine::PrintCudaInfo();
#else
                printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif
                return 0;
            }
            else if (optArg.equals("-u", "--uncomp")) {
                compMode = SEARCH_UNCOMPRESSED;
            }
            else if (optArg.equals("-b", "--both")) {
                compMode = SEARCH_BOTH;
            }
            else if (optArg.equals("-g", "--gpu")) {
                gpuEnable = true;
                nbCPUThread = 0;
            }
            else if (optArg.equals("", "--gpui")) {
                string ids = optArg.arg;
                getInts("--gpui", gpuId, ids, ',');
            }
            else if (optArg.equals("", "--gpux")) {
                string grids = optArg.arg;
                getInts("--gpux", gridSize, grids, ',');
                gpuAutoGrid = false;
            }
            else if (optArg.equals("-t", "--thread")) {
                string strThread = optArg.arg;
                nbCPUThread = std::stoi(strThread);
                tSpecified = true;
            }
            else if (optArg.equals("-i", "--in")) {
                inputFile = optArg.arg;
            }
            else if (optArg.equals("-o", "--out")) {
                outputFile = optArg.arg;
            }
            else if (optArg.equals("-m", "--mode")) {
                searchMode = parseSearchMode(optArg.arg);
            }
            else if (optArg.equals("", "--coin")) {
                coinType = parseCoinType(optArg.arg);
            }
            else if (optArg.equals("", "--range")) {
                string strRange = optArg.arg;
                parseRange(strRange, rangeStart, rangeEnd);
            }
            else if (optArg.equals("-r", "--rkey")) {
                rKey = std::stoi(optArg.arg);
            }
            else if (optArg.equals("-v", "--version")) {
                printf("KeyHunt-Cuda v" RELEASE "\n");
                return 0;
            }
            else {
                printf("Invalid option %s\n", opt.c_str());
                usage();
                return -1;
            }
        }
        catch (const std::exception& e) {
            printf("Error parsing argument %s: %s\n", opt.c_str(), e.what());
            usage();
            return -1;
        }
    }

#ifdef WIN64
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        printf("\nERROR: Could not set control handler\n");
        return 1;
    }
#else
    signal(SIGINT, CtrlHandler);
#endif

    // ------------------------------------------------------------------------
    // Check sanity of parameters

    if (coinType == COIN_ETH && (searchMode == SEARCH_MODE_SX || searchMode == SEARCH_MODE_MX)) {
        printf("Error: Ethereum does not support XPOINT modes\n");
        usage();
        return -1;
    }

    if (coinType == COIN_BTC && (searchMode == SEARCH_MODE_SA || searchMode == SEARCH_MODE_MA)) {
        printf("Error: Bitcoin does not support XPOINT modes\n");
        usage();
        return -1;
    }

    if (searchMode == 0) {
        printf("Error: Search mode must be specified\n");
        usage();
        return -1;
    }

    if (coinType == COIN_ETH && (searchMode == SEARCH_MODE_SX || searchMode == SEARCH_MODE_MX)) {
        if (inputFile.length() == 0) {
            printf("Error: Input file must be specified for Ethereum XPOINT search mode\n");
            usage();
            return -1;
        }
    }

    if (inputFile.length() == 0 && (searchMode == SEARCH_MODE_MA || searchMode == SEARCH_MODE_MX)) {
        printf("Error: Input file must be specified for multiple addresses/xpoints\n");
        usage();
        return -1;
    }

    if (outputFile.length() == 0) {
        printf("Error: Output file must be specified\n");
        usage();
        return -1;
    }

    if (coinType == COIN_ETH && searchMode == SEARCH_MODE_SA && inputFile.length() > 0) {
        printf("Error: Ethereum only supports single address mode without input file\n");
        usage();
        return -1;
    }

    if (rangeEnd.Compare(&rangeStart) <= 0) {
        printf("Error: Invalid range specified\n");
        usage();
        return -1;
    }

    // ------------------------------------------------------------------------
    // Display parameters

    printf("KeyHunt-Cuda v" RELEASE "\n\n");

    printf("Mode     : ");
    switch (searchMode) {
    case SEARCH_MODE_SA:
        printf("Single Address\n");
        break;
    case SEARCH_MODE_MA:
        printf("Multiple Addresses\n");
        break;
    case SEARCH_MODE_SX:
        printf("Single XPoint\n");
        break;
    case SEARCH_MODE_MX:
        printf("Multiple XPoints\n");
        break;
    default:
        break;
    }

    if (coinType == COIN_BTC) {
        printf("Coin Type: Bitcoin\n");
    }
    else if (coinType == COIN_ETH) {
        printf("Coin Type: Ethereum\n");
    }

    printf("Input    : %s\n", inputFile.length() > 0 ? inputFile.c_str() : "stdin");
    printf("Output   : %s\n", outputFile.c_str());

    printf("Range    : ");
    rangeStart.Print();
    printf(" - ");
    rangeEnd.Print();
    printf("\n");

    if (rKey > 0) {
        printf("Random Keyspace: %llu Megakeys\n", (unsigned long long)rKey);
    }

    if (gpuEnable) {
        printf("Using GPU with ID(s): ");
        for (unsigned int i = 0; i < gpuId.size(); i++) {
            printf("%d", gpuId[i]);
            if (i < gpuId.size() - 1) {
                printf(", ");
            }
        }
        printf("\n");

        if (!gpuAutoGrid) {
            printf("GPU GridSize: ");
            for (unsigned int i = 0; i < gridSize.size(); i++) {
                printf("%d", gridSize[i]);
                if (i < gridSize.size() - 1) {
                    printf(", ");
                }
            }
            printf("\n");
        }
    }
    else {
        printf("Using CPU with %d threads\n", nbCPUThread);
    }

    // ------------------------------------------------------------------------
    // Execution

    try {
        KeyHunt hunt;
        hunt.Init(outputFile, rangeStart, rangeEnd, singleAddress, compMode, nbCPUThread, gpuEnable, gpuId, gridSize, rKey, coinType);

        if (inputFile.length() > 0) {
            ifstream in(inputFile, ios::binary);
            if (!in.is_open()) {
                printf("Error: Could not open input file: %s\n", inputFile.c_str());
                return -1;
            }

            hunt.SearchFile(inputFile, searchMode, in);
        }
        else {
            hunt.Search(searchMode, inputFile);
        }

        hunt.Finish();
    }
    catch (std::string err) {
        printf("Error: %s\n", err.c_str());
        return -1;
    }
    catch (std::exception& e) {
        printf("Error: %s\n", e.what());
        return -1;
    }

    return 0;
}
