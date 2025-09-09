#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>

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