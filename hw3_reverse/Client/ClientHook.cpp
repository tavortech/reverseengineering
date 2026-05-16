// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <fstream>
#include <iostream>
#include <ios>
#include <string>
#include <algorithm>
#include <map>
#include <string>
#include <set>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>


using std::ofstream;
using std::endl;
using std::wstring;

ofstream log_file("log-sol.txt");


// change this to the proper signature of the hook
typedef int(*HOOK_TYPE)(const char*);

HOOK_TYPE orig_tgt;

// create cipher parser
std::string DecryptCipher(const std::string& input);

int hookFunc(const char* input) {
    static const std::set<char> skipChars = {'W', '[', 'y'};
    if (skipChars.count(input[0]) == 0) {
        std::string result;
        std::istringstream iss(input);
        for (std::string line; std::getline(iss, line, '\n'); ) {
            // Remove trailing '\r' if present
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                result += "\n";
                continue;
            }
            std::string decryptedLine = DecryptCipher(line);
            result += decryptedLine + "\n";
        }
        return orig_tgt(result.c_str());
    }
    return orig_tgt(input);
}

int evalExpression(const std::string& expr) {
    size_t opPos;
    if ((opPos = expr.find('-')) != std::string::npos) {
        std::string left = expr.substr(0, opPos);
        std::string right = expr.substr(opPos + 1);
        return std::stoi(left) - std::stoi(right);
    }
    if ((opPos = expr.find('+')) != std::string::npos) {
        std::string left = expr.substr(0, opPos);
        std::string right = expr.substr(opPos + 1);
        return std::stoi(left) + std::stoi(right);
    }
    return std::stoi(expr);
}


class MyParser {
public:
    static std::pair<std::string, std::string> parseCipher(const std::string& cipher) {
        if (cipher.empty()) {
            return {"", ""};
        }
        if (cipher.size() >= 3 && (cipher[1] == '+' || cipher[1] == '-')) {
            return {cipher.substr(0, 3), cipher.substr(3)};
        } else {
            return {cipher.substr(0, 1), cipher.substr(1)};
        }
    }

    explicit MyParser(const std::string& cipher) : remaining(cipher) {}

    std::string operator*() {
        return next();
	}

    std::string next(){
        auto p = parseCipher(remaining);
		auto& res = p.first;
		auto& newRemaining = p.second;

        remaining = newRemaining;
        return res;
    }

private:
    std::string remaining;
};

std::string DecryptCipher(const std::string& input) {
    static const std::unordered_map<std::string, int> letterToNibble = {
        {"A", 0x1}, {"J", 0xA}, {"Q", 0xB}, {"K", 0xC}
    };

    std::vector<int> nibblesList;
    MyParser parser(input);

    while (true) {
        std::string token = parser.next();
        if (token.empty()) break;

        auto it = letterToNibble.find(token);
        if (it != letterToNibble.end()) {
            nibblesList.push_back(it->second);
        } else if (token.size() == 3) {
            nibblesList.push_back(evalExpression(token));
        } else {
            nibblesList.push_back(token[0] - '0');
        }
    }

    std::string output;
    for (size_t idx = 0; idx + 1 < nibblesList.size(); idx += 2) {
        int byteVal = (nibblesList[idx] << 4) | nibblesList[idx + 1];
        output += static_cast<char>(byteVal);
    }
    return output;
}






void setHook() {
    // MessageBoxA(NULL, "setHook called", "Debug", MB_OK);
    // char buf[MAX_PATH];
    // GetCurrentDirectoryA(MAX_PATH, buf);
    // std::string logPath = std::string(buf) + "\\log-sol.txt";
    // std::ofstream log_file(logPath, std::ios::app);
    // log_file << "dll attached" << std::endl;

    HMODULE curr_prog = GetModuleHandle(NULL); // get the handle of the main process
    HMODULE target_dll = GetModuleHandle("msvcrt.dll"); // get the handle of the dll conatining the function we want to override
    DWORD lpProtect = 0; 
    
    DWORD IAT_Func_Offset = 0x0000A258;// IAT hook for puts in msvcrt.dll
    
    LPVOID JumpTo;
    LPDWORD IAT_ADDRESS;

    if ((curr_prog == NULL) || (target_dll == NULL)){
        log_file << "couldnt get handles";
        return;
    }
   
    orig_tgt = (HOOK_TYPE) GetProcAddress(target_dll, "puts");
    if (orig_tgt == NULL) {
        log_file << "couldnt find function" << endl;
        return;
    };
    IAT_ADDRESS = (LPDWORD)(curr_prog + IAT_Func_Offset / 4);
    printf("overwriting IAT address: 0x%08x\n", IAT_ADDRESS);
    if ((uintptr_t)(*IAT_ADDRESS) != (uintptr_t)orig_tgt) {
        log_file << "IAT contents does not match - maybe check the offset again" << endl;
        return;
    }

    log_file << "changing IAT entry" << endl << "IAT address: " << IAT_ADDRESS << endl;
    JumpTo = (LPVOID)((char*)&hookFunc);
    VirtualProtect(IAT_ADDRESS, 0x4, PAGE_EXECUTE_READWRITE, &lpProtect);
    memcpy(IAT_ADDRESS, &JumpTo, 0x4);
    VirtualProtect(IAT_ADDRESS, 0x4, PAGE_EXECUTE_READWRITE, &lpProtect);

    log_file << "finished setting hook\n";
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    // char buf[MAX_PATH];
    // GetCurrentDirectoryA(MAX_PATH, buf);
    // MessageBoxA(NULL, buf, "Current Directory", MB_OK);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // MessageBoxA(NULL, "DLL Loaded!", "Debug", MB_OK);
        setHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}