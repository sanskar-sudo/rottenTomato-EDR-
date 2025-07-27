#include <stdio.h>
#include <windows.h>

#define MESSAGE_SIZE 2048
#define MAX_PATH 260

int main() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\rottentomato-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    // Full path to your DLL
    const char dll_full_path[] = "C:\\Users\\vboxuser\\source\\repos\\rottenTomatoDLL\\x64\\Debug\\rottenTomatoDLL.dll";

    printf("Launching injector named pipe server, injecting %s\n", dll_full_path);

    // Creates a named pipe
    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        MESSAGE_SIZE,
        MESSAGE_SIZE,
        0,
        NULL
    );

    if (hServerPipe == INVALID_HANDLE_VALUE) {
        printf("Failed to create named pipe, error: %lu\n", GetLastError());
        return 1;
    }

    while (TRUE) {
        BOOL isPipeConnected = ConnectNamedPipe(hServerPipe, NULL);
        if (!isPipeConnected) {
            printf("Failed to connect to named pipe, error: %lu\n", GetLastError());
            continue;
        }

        wchar_t message[MESSAGE_SIZE] = { 0 };

        if (!ReadFile(hServerPipe, &message, MESSAGE_SIZE, &bytesRead, NULL)) {
            printf("Failed to read from pipe, error: %lu\n", GetLastError());
            DisconnectNamedPipe(hServerPipe);
            continue;
        }

        DWORD target_pid = _wtoi(message);
        printf("~> Received process id %d\n", target_pid);

        HANDLE hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            target_pid
        );

        if (hProcess == NULL) {
            printf("Can't open handle, error: %lu\n", GetLastError());
            DisconnectNamedPipe(hServerPipe);
            continue;
        }
        printf("\tOpen handle on PID: %d\n", target_pid);

        FARPROC loadLibAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
        if (loadLibAddress == NULL) {
            printf("Could not find LoadLibraryA, error: %lu\n", GetLastError());
            CloseHandle(hProcess);
            DisconnectNamedPipe(hServerPipe);
            continue;
        }
        printf("\tFound LoadLibraryA function\n");

        LPVOID vae_buffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (vae_buffer == NULL) {
            printf("Can't allocate memory, error: %lu\n", GetLastError());
            CloseHandle(hProcess);
            DisconnectNamedPipe(hServerPipe);
            continue;
        }
        printf("\tAllocated: %d bytes\n", MAX_PATH);

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, vae_buffer, dll_full_path, strlen(dll_full_path) + 1, &bytesWritten)) {
            printf("Can't write into memory, error: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, vae_buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            DisconnectNamedPipe(hServerPipe);
            continue;
        }
        printf("\tWrote %zu bytes into PID %d memory\n", bytesWritten, target_pid);

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)loadLibAddress,
            vae_buffer, 0, NULL);

        if (hThread == NULL) {
            printf("Can't launch remote thread, error: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, vae_buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            DisconnectNamedPipe(hServerPipe);
            continue;
        }

        printf("\tLaunched remote thread\n");

        // Wait for thread to complete (optional)
        WaitForSingleObject(hThread, INFINITE);

        VirtualFreeEx(hProcess, vae_buffer, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        printf("\tClosed handle\n");

        wchar_t response[MESSAGE_SIZE] = { 0 };
        swprintf_s(response, MESSAGE_SIZE, L"OK");

        DWORD pipeBytesWritten = 0;
        WriteFile(hServerPipe, response, sizeof(response), &pipeBytesWritten, NULL);

        DisconnectNamedPipe(hServerPipe);
        printf("\n\n");
    }

    return 0;
}
