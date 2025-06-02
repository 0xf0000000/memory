using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class ProcessAccess
{
    public const uint VM_OPERATION = 0x0008;
    public const uint VM_READ = 0x0010;
    public const uint VM_WRITE = 0x0020;
    public const uint QUERY_INFO = 0x0400;
}

public class MemoryOperations
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint access,
        bool inheritHandle,
        int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr baseAddr,
        [Out] byte[] buffer,
        int size,
        out IntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr baseAddr,
        byte[] buffer,
        int size,
        out IntPtr bytesWritten);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(
        IntPtr hProcess,
        [Out] IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    private static extern uint GetModuleBaseName(
        IntPtr hProcess,
        IntPtr hModule,
        System.Text.StringBuilder lpBaseName,
        uint nSize);

    public IntPtr AcquireProcessHandle(string procName)
    {
        Process[] procs = Process.GetProcessesByName(procName);
        if (procs.Length == 0) return IntPtr.Zero;
        
        return OpenProcess(
            ProcessAccess.VM_OPERATION | 
            ProcessAccess.VM_READ | 
            ProcessAccess.VM_WRITE | 
            ProcessAccess.QUERY_INFO,
            false,
            procs[0].Id);
    }

    public void ReleaseHandle(IntPtr handle)
    {
        if (handle != IntPtr.Zero)
            CloseHandle(handle);
    }

    public byte[] ReadBytes(IntPtr handle, IntPtr address, int size)
    {
        byte[] data = new byte[size];
        ReadProcessMemory(handle, address, data, size, out _);
        return data;
    }

    public int ReadInt32(IntPtr handle, IntPtr address)
    {
        byte[] data = new byte[4];
        ReadProcessMemory(handle, address, data, 4, out _);
        return BitConverter.ToInt32(data, 0);
    }

    public float ReadSingle(IntPtr handle, IntPtr address)
    {
        byte[] data = new byte[4];
        ReadProcessMemory(handle, address, data, 4, out _);
        return BitConverter.ToSingle(data, 0);
    }

    public void WriteBytes(IntPtr handle, IntPtr address, byte[] data)
    {
        WriteProcessMemory(handle, address, data, data.Length, out _);
    }

    public void WriteInt32(IntPtr handle, IntPtr address, int value)
    {
        byte[] data = BitConverter.GetBytes(value);
        WriteProcessMemory(handle, address, data, data.Length, out _);
    }

    public IntPtr PatternScan(IntPtr handle, string pattern)
    {
        byte[] patternBytes = ParsePattern(pattern);
        IntPtr[] mods = new IntPtr[256];
        if (!EnumProcessModules(handle, mods, (uint)(IntPtr.Size * mods.Length), out uint needed))
            return IntPtr.Zero;

        uint count = needed / (uint)IntPtr.Size;
        var nameBuilder = new System.Text.StringBuilder(260);

        for (int i = 0; i < count; i++)
        {
            GetModuleBaseName(handle, mods[i], nameBuilder, (uint)nameBuilder.Capacity);
            if (nameBuilder.ToString().Contains(".exe"))
            {
                return ScanModule(handle, mods[i], patternBytes);
            }
        }
        return IntPtr.Zero;
    }

    private byte[] ParsePattern(string pattern)
    {
        List<byte> bytes = new List<byte>();
        string[] hex = pattern.Split(' ');
        
        foreach (string h in hex)
        {
            if (h == "??")
            {
                bytes.Add(0x00);
            }
            else
            {
                bytes.Add(Convert.ToByte(h, 16));
            }
        }
        return bytes.ToArray();
    }

    private IntPtr ScanModule(IntPtr handle, IntPtr module, byte[] pattern)
    {
        const int CHUNK_SIZE = 0x1000;
        byte[] buffer = new byte[CHUNK_SIZE];
        IntPtr current = module;

        while (true)
        {
            if (!ReadProcessMemory(handle, current, buffer, CHUNK_SIZE, out _))
                break;

            for (int i = 0; i < CHUNK_SIZE - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern[j] != 0x00 && pattern[j] != buffer[i + j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return current + i;
            }
            current += CHUNK_SIZE;
        }
        return IntPtr.Zero;
    }
}