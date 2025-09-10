#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <psapi.h>

DWORD findAMongUsProcess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    process.dwSize = sizeof(process);
    
    Process32First(snapshot, &process);
    do {
        std::string processName = process.szExeFile;
        if (processName == "Among Us.exe") {
            CloseHandle(snapshot);
            std::cout << "found AmongUs process (PID: " << process.th32ProcessID << ")" << std::endl;
            return process.th32ProcessID;
        }
    } while (Process32Next(snapshot, &process));
    
    CloseHandle(snapshot);
    return 0; 
}

void checkSuspiciousDLLs(DWORD targetProcessID, const std::string& processName) {
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, targetProcessID);
    if (hModuleSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(moduleEntry);
    
    std::cout << "checking DLLs loaded in " << processName << ":" << std::endl;
    
    Module32First(hModuleSnap, &moduleEntry);
    do {
        std::string moduleName = moduleEntry.szModule;
        std::string modulePath = moduleEntry.szExePath;
        
        // Check for suspicious DLL names
        if (moduleName.find("cheat") != std::string::npos ||
            moduleName.find("hack") != std::string::npos ||
            moduleName.find("inject") != std::string::npos ||
            modulePath.find("temp") != std::string::npos ||
            moduleName.find("speedhack") != std::string::npos ||
            moduleName.find("trainer") != std::string::npos) {
            
            std::cout << "SUSPICIOUS DLL: " << moduleName 
                      << " (" << modulePath << ")" << std::endl;
        }
        
        // show all DLLs 
        // std::cout << "  DLL: " << moduleName << std::endl;
        
    } while (Module32Next(hModuleSnap, &moduleEntry));
    
    CloseHandle(hModuleSnap);
}

int main() {
    // create list of threats 
    std::vector<std::string> threatList = {
        "cheatengine-x86_64-SSE4-AVX2.exe",
        "x64dbg.exe",
        "ollydbg.exe", 
        "ida.exe",
        "ida64.exe",
        "ghidra.exe"
    };

    std::cout << "Anti-cheat detector started. Monitoring " << threatList.size() << " threats.\n" << std::endl;

    // make it scan continuously
    while (true) {
        std::cout << "Ctrl + C to stop the scanning" << std::endl;
        // list of all running processes 
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        // detect among us running
        DWORD amongUsID = findAMongUsProcess();
        if (amongUsID != 0) {
            checkSuspiciousDLLs(amongUsID, "Among Us.exe");
        }

        // container of info on each process
        PROCESSENTRY32 process;
        process.dwSize = sizeof(process);

        Process32First(snapshot, &process);

        do {
            std::string processName = process.szExeFile;

            for (const std::string& threat : threatList) {
                if (processName == threat) {
                    std::cout << "THREAT DETECTED: " << processName 
                              << " (PID: " << process.th32ProcessID << ")" << std::endl;
                    break;
                }
            }
        } while (Process32Next(snapshot, &process));

        CloseHandle(snapshot);

        std::cout << "Scan complete. Waiting 3 seconds..." << std::endl;

        // make it scan every few seconds 
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return 0;
}