# RottenTomato EDR 


<div align="center">
  <img src="https://images.squarespace-cdn.com/content/v1/63e663bb029b8054ba134992/6c8f36c0-0d25-4e5f-bf74-f2beb1ea99f6/TTP_Mascot_Illo_TomatoGuy.png?format=1500w" alt="Alt Text for the image" width="300"/>
</div>


A project that builds a simple Windows EDR (Endpoint Detection and Response) from the ground up, starting with a basic kernel driver and progressively adding more advanced security features.  

## About This Project  

This repository documents the journey of creating a security tool that can monitor and interact with the Windows operating system at a low level. The primary goal is to provide a clear, step-by-step guide for anyone interested in learning about:  

- Windows Kernel Driver Development  
- Process Monitoring and Control  
- Inter-process Communication (Kernel to User-mode)  
- API Hooking for Behavioral Analysis  

## Project Stages  

The repository is organized into folders, each representing a key stage in the development process:  

1. **Basic Driver**: The "Hello, World!" of kernel drivers. This stage covers creating, loading, and unloading a minimal driver in Windows.  
   **Simple Detection**: Introduces the first EDR capability by adding a kernel-level callback to monitor and block processes based on their name (e.g., `mimikatz.exe`).  
2. **Advanced Detection**: Evolves the project into a more realistic, multi-component architecture. This stage separates responsibilities between a kernel driver (as a sensor) and user-mode agents (for analysis and response), including a DLL for API hooking.  

Each folder contains the complete source code for that particular stage.  

## Getting Started  

To build and run the code in this repository, you will need a Windows development environment.  

### Prerequisites  

- A Windows 10/11 Virtual Machine for safe testing.  
- Visual Studio (latest version recommended).  
- The Windows Driver Kit (WDK) and the corresponding Visual Studio extension.  
- *(For Advanced Detection stage)* The MinHook library for API hooking.  

### General Steps  

1. **Set up your test environment**: On your VM, enable Test Signing mode by running `bcdedit /set testsigning on` as an administrator and rebooting.  
2. **Build a stage**: Navigate to a project folder (e.g., `2-Simple-Detection`), open the source code in a Visual Studio KMDF project, and build it for the x64 platform.  
3. **Run the code**: Follow the specific instructions within each folder's README to load the driver and/or run the user-mode agents.  
4. **Observe**: Use DebugView from Sysinternals to see the debug messages printed by the driver.  

