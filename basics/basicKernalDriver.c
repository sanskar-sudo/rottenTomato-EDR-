#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>

// Define the device name and symbolic link for the RottenTomato driver
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\RottenTomato");  // Kernel-visible device name
UNICODE_STRING SYM_LINK    = RTL_CONSTANT_STRING(L"\\??\\RottenTomato");      // User-visible symbolic link

// Unload routine called when the driver is being unloaded
void UnloadRottenTomato(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "RottenTomato: Unloading driver...\n");

    // Delete the device object created by the driver
    IoDeleteDevice(DriverObject->DeviceObject);

    // Remove the symbolic link to the device
    IoDeleteSymbolicLink(&SYM_LINK);
}

// Entry point for the driver — called when the driver is loaded
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); // Not used in this driver

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "RottenTomato: Initializing driver...\n");

    NTSTATUS status;                   // Status variable for function return codes
    PDEVICE_OBJECT DeviceObject;       // Pointer to created device object

    // Create a device object for communication
    status = IoCreateDevice(
        DriverObject,                 // Driver object passed by system
        0,                            // No additional device extension space needed
        &DEVICE_NAME,                // Name of the device
        FILE_DEVICE_UNKNOWN,         // Device type is unspecified
        0,                            // No special characteristics
        FALSE,                        // Not exclusive; multiple handles allowed
        &DeviceObject                // Output: created device object
    );

    // Check if device creation failed
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RottenTomato: Failed to create device\n");
        return status;
    }

    // Create a symbolic link so user-mode apps can access the driver
    status = IoCreateSymbolicLink(&SYM_LINK, &DEVICE_NAME);

    // Check if symbolic link creation failed
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RottenTomato: Failed to create symbolic link\n");
        IoDeleteDevice(DeviceObject); // Clean up created device
        return status;
    }

    // Set the driver's unload routine
    DriverObject->DriverUnload = UnloadRottenTomato;

    return status; // Return the final status (should be STATUS_SUCCESS)
}
