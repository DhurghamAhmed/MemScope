[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Command,
    [string]$WorkingDirectory = (Get-Location).Path,
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class MediumLauncher
{
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    const uint TOKEN_ALL = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT
                         | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID;

    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const uint LUA_TOKEN = 0x4;
    const int TokenIntegrityLevel = 25;
    const uint SE_GROUP_INTEGRITY = 0x20;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x400;
    const uint LOGON_WITH_PROFILE = 0x1;
    const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes,
        int impersonationLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(IntPtr existing, uint flags,
        uint disableSidCount, IntPtr sidsToDisable,
        uint deletePrivilegeCount, IntPtr privilegesToDelete,
        uint restrictedSidCount, IntPtr sidsToRestrict, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, uint length);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags,
        string applicationName, string commandLine, uint creationFlags,
        IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll")]
    static extern IntPtr FreeSid(IntPtr sid);

    public static int Run(string commandLine, string workingDirectory, int timeoutSeconds, bool luaToken)
    {
        IntPtr own = IntPtr.Zero, duplicated = IntPtr.Zero, restricted = IntPtr.Zero;
        IntPtr mediumSid = IntPtr.Zero, labelBuffer = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL, out own))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");

            if (!DuplicateTokenEx(own, TOKEN_ALL, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out duplicated))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");

            if (luaToken)
            {
                if (!CreateRestrictedToken(duplicated, LUA_TOKEN, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken");
            }
            else
            {
                restricted = duplicated;
                duplicated = IntPtr.Zero;
            }

            if (!ConvertStringSidToSidW("S-1-16-8192", out mediumSid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertStringSidToSidW");

            TOKEN_MANDATORY_LABEL label = new TOKEN_MANDATORY_LABEL();
            label.Label.Sid = mediumSid;
            label.Label.Attributes = SE_GROUP_INTEGRITY;
            uint size = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + GetLengthSid(mediumSid);
            labelBuffer = Marshal.AllocHGlobal((int)size);
            Marshal.StructureToPtr(label, labelBuffer, false);

            if (!SetTokenInformation(restricted, TokenIntegrityLevel, labelBuffer, size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation");

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = "winsta0\\default";
            PROCESS_INFORMATION pi;

            if (!CreateProcessWithTokenW(restricted, 0, null, commandLine,
                    CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, workingDirectory, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithTokenW");

            uint wait = timeoutSeconds <= 0 ? INFINITE : (uint)(timeoutSeconds * 1000);
            uint result = WaitForSingleObject(pi.hProcess, wait);
            uint exitCode;
            if (result != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                throw new TimeoutException("the medium-integrity child did not exit within " + timeoutSeconds + "s");
            }
            if (!GetExitCodeProcess(pi.hProcess, out exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess");

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return (int)exitCode;
        }
        finally
        {
            if (labelBuffer != IntPtr.Zero) Marshal.FreeHGlobal(labelBuffer);
            if (mediumSid != IntPtr.Zero) FreeSid(mediumSid);
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (duplicated != IntPtr.Zero) CloseHandle(duplicated);
            if (own != IntPtr.Zero) CloseHandle(own);
        }
    }
}
'@

$quoted = $Command | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
$commandLine = $quoted -join ' '

Write-Host "medium-integrity run: $commandLine"
Write-Host "working directory:    $WorkingDirectory"

$code = $null
foreach ($mode in @($true, $false)) {
    $label = if ($mode) { 'uac-filtered (LUA_TOKEN) + medium integrity' } else { 'medium integrity only' }
    try {
        $code = [MediumLauncher]::Run($commandLine, $WorkingDirectory, $TimeoutSeconds, $mode)
        if ($code -eq -1073741502) {
            Write-Host "token mode rejected by the window station: $label"
            $code = $null
            continue
        }
        Write-Host "token mode: $label"
        break
    }
    catch {
        Write-Host "token mode failed: $label -- $($_.Exception.Message)"
        $code = $null
    }
}
if ($null -eq $code) { throw 'no usable non-elevated token mode was found on this host' }
Write-Host "exit code: $code"
exit $code
