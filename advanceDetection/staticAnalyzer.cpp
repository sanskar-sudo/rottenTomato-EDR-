
#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")

#define MESSAGE_SIZE 2048

BOOL VerifyEmbeddedSignature(const wchar_t* binaryPath) {
    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = binaryPath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    BOOL isSigned;
    switch (lStatus) {
    case ERROR_SUCCESS:
        isSigned = TRUE;
        break;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
    case TRUST_E_PROVIDER_UNKNOWN:
    case TRUST_E_EXPLICIT_DISTRUST:
    case CRYPT_E_SECURITY_SETTINGS:
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        isSigned = TRUE;
        break;
    case TRUST_E_NOSIGNATURE:
        isSigned = FALSE;
        break;
    default:
        isSigned = FALSE;
        break;
    }

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return isSigned;
}

BOOL ListImportedFunctions(const wchar_t* binaryPath) {
    BOOL isOpenProcessPresent = FALSE;
    BOOL isVirtualAllocExPresent = FALSE;
    BOOL isWriteProcessMemoryPresent = FALSE;
    BOOL isCreateRemoteThreadPresent = FALSE;

    HMODULE hModule = LoadLibraryEx(binaryPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule != NULL) {
        IMAGE_NT_HEADERS* ntHeaders = ImageNtHeader(hModule);
        if (ntHeaders != NULL) {
            IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            while (importDesc->Name != 0) {
                const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);

                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->OriginalFirstThunk);
                while (thunk->u1.AddressOfData != 0) {
                    if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + thunk->u1.AddressOfData);

                        if (strcmp("OpenProcess", importByName->Name) == 0)
                            isOpenProcessPresent = TRUE;
                        if (strcmp("VirtualAllocEx", importByName->Name) == 0)
                            isVirtualAllocExPresent = TRUE;
                        if (strcmp("WriteProcessMemory", importByName->Name) == 0)
                            isWriteProcessMemoryPresent = TRUE;
                        if (strcmp("CreateRemoteThread", importByName->Name) == 0)
                            isCreateRemoteThreadPresent = TRUE;
                    }
                    thunk++;
                }
                importDesc++;
            }
        }
        FreeLibrary(hModule);
    }

    return (isOpenProcessPresent && isVirtualAllocExPresent && isWriteProcessMemoryPresent && isCreateRemoteThreadPresent);
}

BOOL lookForSeDebugPrivilegeString(const wchar_t* filename) {
    FILE* file;
    _wfopen_s(&file, filename, L"rb");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);
        char* buffer = (char*)malloc(file_size);
        if (buffer != NULL) {
            if (fread(buffer, 1, file_size, file) == file_size) {
                const char* search_string = "SeDebugPrivilege";
                size_t search_length = strlen(search_string);
                for (int i = 0; i <= file_size - search_length; i++) {
                    int j = 0;
                    for (; j < search_length; j++) {
                        if (buffer[i + j] != search_string[j]) break;
                    }
                    if (j == search_length) {
                        free(buffer);
                        fclose(file);
                        return TRUE;
                    }
                }
            }
            free(buffer);
        }
        fclose(file);
    }
    return FALSE;
}

int main() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\rottentomato-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    printf("Launching analyzer named pipe server\n");

    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        MESSAGE_SIZE,
        MESSAGE_SIZE,
        0,
        NULL
    );

    while (TRUE) {
        BOOL isPipeConnected = ConnectNamedPipe(hServerPipe, NULL);

        if (isPipeConnected) {
            ReadFile(
                hServerPipe,
                &target_binary_file,
                MESSAGE_SIZE,
                &bytesRead,
                NULL
            );

            printf("~> Received binary file %ws\n", target_binary_file);

            BOOL isSeDebugPrivilegeStringPresent = lookForSeDebugPrivilegeString(target_binary_file);
            if (isSeDebugPrivilegeStringPresent)
                printf("\t\033[31mFound SeDebugPrivilege string.\033[0m\n");
            else
                printf("\t\033[32mSeDebugPrivilege string not found.\033[0m\n");

            BOOL isDangerousFunctionsFound = ListImportedFunctions(target_binary_file);
            if (isDangerousFunctionsFound)
                printf("\t\033[31mDangerous functions found.\033[0m\n");
            else
                printf("\t\033[32mNo dangerous functions found.\033[0m\n");

            BOOL isSigned = VerifyEmbeddedSignature(target_binary_file);
            if (isSigned)
                printf("\t\033[32mBinary is signed.\033[0m\n");
            else
                printf("\t\033[31mBinary is not signed.\033[0m\n");

            wchar_t response[MESSAGE_SIZE] = { 0 };
            if (isSigned) {
                swprintf_s(response, MESSAGE_SIZE, L"OK\0");
                printf("\t\033[32mStaticAnalyzer allows\033[0m\n");
            }
            else {
                if (isDangerousFunctionsFound || isSeDebugPrivilegeStringPresent) {
                    swprintf_s(response, MESSAGE_SIZE, L"KO\0");
                    printf("\n\t\033[31mStaticAnalyzer denies\033[0m\n");
                }
                else {
                    swprintf_s(response, MESSAGE_SIZE, L"OK\0");
                    printf("\n\t\033[32mStaticAnalyzer allows\033[0m\n");
                }
            }

            DWORD bytesWritten = 0;
            WriteFile(hServerPipe, response, MESSAGE_SIZE, &bytesWritten, NULL);
        }

        DisconnectNamedPipe(hServerPipe);
        printf("\n\n");
    }

    return 0;
}
