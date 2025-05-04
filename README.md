# AnotherShellcodeInjector
Proof of concept demonstrating shellcode injection into Windows processes using C#.

### What is shellcode?

Shellcode is a small piece of code, usually written in assembly language, designed to be injected into memory and executed directly. Its name comes from the fact that traditionally its purpose was to obtain a shell or system access.

### About this PoC

This tool allows:

Inject custom shellcode into a remote process
Allocate executable memory in an external process
Create a remote thread to execute the injected code.

### Generating shellcode
To generate compatible shellcode, it is recommended to use Donut, a tool that converts .NET executables into positionally independent shellcode.
Technical details


#### The injector works using the classic process injection technique:

* Gets a handle to the target process with OpenProcess()
* Reserves executable memory with VirtualAllocEx()
* Writes the shellcode with WriteProcessMemory()
* Changes memory permissions to executable with VirtualProtectEx()
* Creates a remote thread with CreateRemoteThread() that points to the shellcode.
