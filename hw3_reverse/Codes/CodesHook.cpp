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
typedef int(*HOOK_TYPE)(const char* s1, const char* s2); //strcmp(const char*, const char*)

HOOK_TYPE orig_tgt;

int hookFunc(const char* s1, const char* s2) {
    // printf("hookFunc called with s1: %s, s2: %s\n", s1, s2);
    if ((std::string)s2 == "ROBBER_CAPTURED") {
        // printf("hookFunc called with s1: %s, s2: %s\n", s1, s2);
        return 0;
    }
    return 1;
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
    
    DWORD IAT_Func_Offset = 0x00009294;// IAT hook for puts in msvcrt.dll
    
    LPVOID JumpTo;
    LPDWORD IAT_ADDRESS;

    if ((curr_prog == NULL) || (target_dll == NULL)){
        log_file << "couldnt get handles";
        return;
    }
   
    orig_tgt = (HOOK_TYPE) GetProcAddress(target_dll, "strcmp");
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