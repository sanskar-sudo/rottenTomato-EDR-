Advanced Detection (Multi-Component EDR)

This folder represents a major architectural shift, moving towards a more realistic EDR design with multiple components working together. The detection logic is moved from the kernel into user-mode agents.

* **Purpose:** To separate kernel-mode responsibilities (monitoring) from user-mode responsibilities (analysis and response), improving stability and flexibility.
* **Architecture:**
    1.  The **Kernel Driver** (`driver.c`) detects a new process.
    2.  It sends the process's file path to the **Static Analyzer** (`staticAnalyzer.cpp`) via a named pipe.
    3.  The **Static Analyzer** inspects the binary for malicious indicators. If the binary is suspicious, it tells the driver to block it.
    4.  If the binary is allowed, the driver sends the new process ID (PID) to the **Remote Injector** (`remoteInjector.cpp`).
    5.  The **Remote Injector** injects a **Hooking DLL** (`rottenTomato.dll`) into the newly created process.
    6.  The **Hooking DLL** uses API hooking (via MinHook) to monitor the process's behavior from the inside, such as blocking attempts to allocate executable memory.

#### Component Breakdown

* **`driver.c` (Kernel Driver):**
    * Its only job is to be a kernel-level sensor.
    * Uses `PsSetCreateProcessNotifyRoutineEx` to detect process creation.
    * Communicates with the user-mode agents via two named pipes: `\\??\\pipe\\rottenTomato-analyzer` and `\\??\\pipe\\rottenTomato-injector`.
    * It makes no decisions itself; it only acts on the "OK" or "KO" response from the Static Analyzer.

* **`staticAnalyzer.cpp` (User-Mode Agent):**
    * Listens on the `rottenTomato-analyzer` named pipe.
    * Performs static analysis on the binary path received from the driver.
    * Checks for:
        * A valid digital signature.
        * Suspicious imported functions (e.g., `OpenProcess`, `VirtualAllocEx`).
        * The presence of the string `"SeDebugPrivilege"`.
    * Sends `"KO"` (block) or `"OK"` (allow) back to the driver.

* **`remoteInjector.cpp` (User-Mode Agent):**
    * Listens on the `rottenTomato-injector` named pipe.
    * Receives the Process ID (PID) of allowed processes from the driver.
    * Uses standard process injection techniques (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) to load the hooking DLL into the target process.

* **`rottenTomato.dll` (Hooking DLL):**
    * Designed to be injected into other processes.
    * Uses the [MinHook](https://github.com/TsudaKageyu/minhook) library to intercept API calls.
    * Hooks `ntdll!NtAllocateVirtualMemory` to monitor memory allocations.
    * If a program attempts to allocate memory with Read, Write, and Execute permissions (`PAGE_EXECUTE_READWRITE`)—a common tactic for shellcode—the DLL will display a message box and terminate the process.

---

## How to Build and Run

### Prerequisites

1.  **Windows OS:** Windows 10 or 11 (for testing, preferably in a VM).
2.  **Visual Studio:** The latest version is recommended.
3.  **Windows Driver Kit (WDK):** Ensure you install the WDK and the Visual Studio extension.
4.  **MinHook Library:** Download MinHook and configure the `rottenTomato.dll` project to include its header and library files.

### Building the Solution

1.  Create separate Visual Studio projects for each of the four components.
2.  Build all components for the **x64** platform.
3.  After building, copy `rottenTomato.dll` to the same directory as `remoteInjector.exe` (e.g., `YourSolution\x64\Debug\`).

### Running the EDR

1.  **Enable Test Signing Mode:** Open Command Prompt as an **Administrator** and run:
    ```cmd
    bcdedit /set testsigning on
    ```
    **Reboot your machine** for this to take effect.

2.  **View Debug Messages:** Run [DebugView (DbgView.exe)](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) and enable **"Capture Kernel"** in the `Capture` menu.

3.  **Launch the EDR:** Create a batch script (`start_edr.bat`) to launch all components in the correct order. Run it as **Administrator**.
    ```batch
    @echo off
    ECHO Starting RottenTomato EDR components...

    REM Start the user-mode agents first
    ECHO [+] Starting Static Analyzer...
    start "Static Analyzer" cmd /k "C:\path\to\your\project\x64\Debug\staticAnalyzer.exe"

    ECHO [+] Starting Remote Injector...
    start "Remote Injector" cmd /k "C:\path\to\your\project\x64\Debug\remoteInjector.exe"

    timeout /t 2 >nul

    REM Load the kernel driver
    ECHO [+] Loading Kernel Driver...
    sc.exe create rottenTomatoEDR type=kernel binPath="C:\path\to\your\project\x64\Debug\driver.sys"
    sc.exe start rottenTomatoEDR

    echo.
    ECHO RottenTomato EDR is now running.
    pause
    ```

4.  **Stop and Unload the EDR:** Close the agent command prompt windows, then run the following in an admin prompt:
    ```cmd
    sc.exe stop rottenTomatoEDR
    sc.exe delete rottenTomatoEDR
    ```
