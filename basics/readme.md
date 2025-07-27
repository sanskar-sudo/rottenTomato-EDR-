### 1. Basic Driver

This folder contains the foundational source code for a minimal Windows kernel driver.

**File: `BasicDriver.c`**

* **Purpose:** To create a loadable and unloadable kernel driver.
* **Functionality:**
    * **`DriverEntry`:** The main entry point that gets called when the driver is loaded. It performs the following actions:
        * Creates a kernel device object named `\Device\RottenTomato`.
        * Creates a user-visible symbolic link `\??\RottenTomato`, which allows user-mode applications to communicate with the driver in the future.
    * **`UnloadRottenTomato`:** The unload routine that cleans up resources when the driver is stopped. It deletes the device object and the symbolic link.
* **Behavior:** This driver doesn't have any security features. It simply loads into the kernel, creates its device, and waits to be unloaded. It's the "Hello, World!" of kernel drivers.

### 2. Mimikatz Detection

This folder enhances the basic driver by adding the first EDR feature: process monitoring and blocking.

**File: `DetectingMimikatz.c`**

* **Purpose:** To actively monitor and block the creation of specific processes.
* **New Functionality:**
    * **`PsSetCreateProcessNotifyRoutineEx`:** In `DriverEntry`, this Windows API is called to register a callback function. The kernel will now call our function every time a new process is created on the system.
    * **`CreateProcessNotifyRoutine`:** This is the callback function that contains our detection logic.
        * It inspects the `CommandLine` of the process being created.
        * If the command line contains the string `"mimikatz"`, it sets the `CreationStatus` to `STATUS_ACCESS_DENIED`, telling the kernel to block the process from running.
        * It also includes a sample rule to allow `"notepad"`.
* **Behavior:** When this driver is loaded, it actively protects the system by preventing any process with "mimikatz" in its name from launching.

---

## How to Build and Run

To compile and test the RottenTomato driver, you will need a test environment, preferably a Windows Virtual Machine.

### Prerequisites

1.  **Windows OS:** Windows 10 or 11 (for testing).
2.  **Visual Studio:** The latest version is recommended.
3.  **Windows Driver Kit (WDK):** Ensure you install the WDK and the Visual Studio extension that corresponds to your version of Visual Studio.

### Building the Driver

1.  Open Visual Studio.
2.  Create a new project using the **"Kernel Mode Driver, Empty (KMDF)"** template.
3.  Copy the source code from either `BasicDriver.c` or `DetectingMimikatz.c` into your main project file.
4.  Build the solution for the **x64** platform. This will produce a `RottenTomato.sys` file.

### Running the Driver

1.  **Enable Test Signing Mode:** Drivers used for testing must be loaded in a special mode. Open Command Prompt as an **Administrator** and run:
    ```cmd
    bcdedit /set testsigning on
    ```
    **You must reboot your machine** for this change to take effect.

2.  **View Debug Messages:** Download and run [DebugView (DbgView.exe)](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) from Microsoft Sysinternals. In the `Capture` menu, make sure **"Capture Kernel"** is enabled. This will show the `DbgPrintEx` messages from the driver.

3.  **Load the Driver:** Copy the `RottenTomato.sys` file to your test machine. In an Administrator Command Prompt, create and start the service for the driver:
    ```cmd
    // Replace "C:\path\to\your\driver\RottenTomato.sys" with the actual path
    sc.exe create RottenTomato type=kernel binPath="C:\path\to\your\driver\RottenTomato.sys"
    sc.exe start RottenTomato
    ```
    You should see the "Initializing driver..." message in DbgView.

4.  **Test the Driver:**
    * If running the `DetectingMimikatz` version, try to run a file named `mimikatz.exe`. The process should be blocked with an "Access is denied" error.
    * You will see the "Process denied" message in DbgView.

5.  **Stop and Unload the Driver:**
    ```cmd
    sc.exe stop RottenTomato
    sc.exe delete RottenTomato
    ```
    You should see the "Unloading driver..." message in DbgView.
