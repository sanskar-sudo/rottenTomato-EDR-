# 🍅 RottenTomato EDR

An educational project that builds a simple Windows EDR (Endpoint Detection and Response) from the ground up. Starting with a basic kernel driver, this project gradually adds more advanced security features.

---

## 📘 About This Project

This repository documents the journey of creating a security tool capable of monitoring and interacting with the Windows operating system at a low level. The primary goal is to provide a **clear, step-by-step guide** for anyone interested in learning about:

- 🧠 Windows Kernel Driver Development  
- 🔍 Process Monitoring and Control  
- 🔄 Inter-process Communication (Kernel to User-mode)  
- 🪝 API Hooking for Behavioral Analysis  

---

## 🧱 Project Stages

The repository is organized into folders, each representing a key stage in the development process:

### 1. **Basic Driver**
> The "Hello, World!" of kernel drivers.  
Learn to create, load, and unload a minimal driver in Windows.

### 2. **Simple Detection**
> Adds basic EDR functionality.  
Implements a kernel-level callback to monitor and block processes based on name (e.g., `mimikatz.exe`).

### 3. **Advanced Detection**
> Moves to a more realistic, multi-component architecture.  
Includes a kernel-mode sensor, user-mode analysis agents, and a DLL for API hooking using MinHook.

Each folder contains the **complete source code** and step-by-step instructions for that stage.

---

## 🛠 Getting Started

### ✅ Prerequisites

- Windows 10/11 **Virtual Machine** for safe testing  
- **Visual Studio** (latest version recommended)  
- **Windows Driver Kit (WDK)** and VS extension  
- (For Advanced Detection) **[MinHook](https://github.com/TsudaKageyu/minhook)** for API hooking  

---

### ⚙️ General Steps

1. **Set up your test environment**  
   Enable Test Signing Mode:  
   ```bash
   bcdedit /set testsigning on
