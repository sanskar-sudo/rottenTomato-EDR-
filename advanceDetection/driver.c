#include <ntddk.h>

// Global variables
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\rottenTomatoEDR");
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\rottenTomatoEDR");

// Forward declaration of the unload routine and the callback
void UnloadRottenTomatoEDR(_In_ PDRIVER_OBJECT DriverObject);
void CreateProcessNotifyRoutine(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo);

// The main entry point for the driver
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Initializing the driver\n");
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;

    // Set the function to be called when the driver is unloaded
    DriverObject->DriverUnload = UnloadRottenTomatoEDR;

    // Create a device object for our driver
    status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Device creation failed: 0x%X\n", status);
        return status;
    }

    // Create a symbolic link so user-mode applications can communicate with the driver
    status = IoCreateSymbolicLink(&SYM_LINK, &DEVICE_NAME);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Symlink creation failed: 0x%X\n", status);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Register our process creation callback routine
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to set callback routine: 0x%X\n", status);
        IoDeleteSymbolicLink(&SYM_LINK);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}

// The routine that is called when a process is created or terminated
void CreateProcessNotifyRoutine(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(process);

    if (createInfo) {
        createInfo->CreationStatus = STATUS_SUCCESS;

        HANDLE hPipeAnalyzer, hPipeInjector;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        NTSTATUS status;

        UNICODE_STRING pipeNameAnalyzer = RTL_CONSTANT_STRING(L"\\??\\pipe\\rottenTomato-analyzer");
        UNICODE_STRING pipeNameInjector = RTL_CONSTANT_STRING(L"\\??\\pipe\\rottenTomato-injector");

        // Connect to Static Analyzer Agent
        InitializeObjectAttributes(&objAttr, &pipeNameAnalyzer, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwCreateFile(&hPipeAnalyzer, GENERIC_WRITE | GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to open analyzer pipe: 0x%X\n", status);
            return;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Sending '%wZ' to Static Analyzer\n", createInfo->ImageFileName);

        status = ZwWriteFile(hPipeAnalyzer, NULL, NULL, NULL, &ioStatusBlock,
                             createInfo->ImageFileName->Buffer, createInfo->ImageFileName->Length, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to write to analyzer pipe: 0x%X\n", status);
            ZwClose(hPipeAnalyzer);
            return;
        }

        wchar_t response[10] = { 0 };
        status = ZwReadFile(hPipeAnalyzer, NULL, NULL, NULL, &ioStatusBlock,
                            response, sizeof(response) - sizeof(WCHAR), NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to read from analyzer pipe: 0x%X\n", status);
            ZwClose(hPipeAnalyzer);
            return;
        }
        ZwClose(hPipeAnalyzer);

        if (wcscmp(response, L"KO") == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Static Analyzer denied process. Blocking.\n");
            createInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Static Analyzer allowed process. Forwarding to Injector.\n");

        // Connect to Remote Injector Agent
        InitializeObjectAttributes(&objAttr, &pipeNameInjector, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwCreateFile(&hPipeInjector, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL,
                              FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to open injector pipe: 0x%X\n", status);
            return;
        }

        WCHAR pidBuffer[20];
        UNICODE_STRING pidUnicodeString;
        pidUnicodeString.Buffer = pidBuffer;
        pidUnicodeString.Length = 0;
        pidUnicodeString.MaximumLength = sizeof(pidBuffer);

        status = RtlIntegerToUnicodeString((ULONG)(ULONG_PTR)pid, 10, &pidUnicodeString);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to convert PID to string: 0x%X\n", status);
            ZwClose(hPipeInjector);
            return;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Sending PID %wZ to Remote Injector\n", &pidUnicodeString);

        status = ZwWriteFile(hPipeInjector, NULL, NULL, NULL, &ioStatusBlock,
                             pidUnicodeString.Buffer, pidUnicodeString.Length, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomatoEDR: Failed to write to injector pipe: 0x%X\n", status);
        }

        ZwClose(hPipeInjector);
    }
}

// The routine that is called when the driver is unloaded
void UnloadRottenTomatoEDR(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Unloading routine called\n");
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    IoDeleteSymbolicLink(&SYM_LINK);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomatoEDR: Driver unloaded successfully.\n");
}
