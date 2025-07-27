#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>

// Global variables
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\rottenTomato"); // Internal device name
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\rottenTomato");        // Symlink

// Handle incoming notifications about new/terminated processes
void CreateProcessNotifyRoutine(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(pid);

    // Never forget this if check because if you don't, you'll end up crashing your Windows system ;P
    if (createInfo != NULL) {
        // Compare the command line of the launched process to the notepad string
        if (wcsstr(createInfo->CommandLine->Buffer, L"notepad") != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Process (%ws) allowed.\n", createInfo->CommandLine->Buffer);
            // Process allowed
            createInfo->CreationStatus = STATUS_SUCCESS;
        }

        // Compare the command line of the launched process to the mimikatz string
        if (wcsstr(createInfo->CommandLine->Buffer, L"mimikatz") != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Process (%ws) denied.\n", createInfo->CommandLine->Buffer);
            // Process denied
            createInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}

void UnloadrottenTomato(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "rottenTomato: Unloading routine called\n");
    // Unset the callback
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    // Prevent compiler error in level 4 warnings
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Initializing the driver\n");

    // Variable that will store the output of WinAPI functions
    NTSTATUS status;

    // Setting the unload routine to execute
    DriverObject->DriverUnload = UnloadrottenTomato;

    // Initializing a device object and creating it
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING deviceName = DEVICE_NAME;
    UNICODE_STRING symlinkName = SYM_LINK;
    status = IoCreateDevice(
        DriverObject,     // our driver object,
        0,        // no need for extra bytes,
        &deviceName,           // the device name,
        FILE_DEVICE_UNKNOWN,   // device type,
        0,        // characteristics flags,
        FALSE,       // not exclusive,
        &DeviceObject     // the resulting pointer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Registers the kernel callback
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "rottenTomato: Driver created\n");
    return STATUS_SUCCESS;
}
