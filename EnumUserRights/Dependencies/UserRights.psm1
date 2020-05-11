<#

VERSION   DATE          AUTHOR
1.0       2015-03-10    Tony Pombo
    - Initial Release

1.1       2015-03-11    Tony Pombo
    - Added enum Rights, and configured functions to use it
    - Fixed a couple typos in the help

1.2       2015-11-13    Tony Pombo
    - Fixed exception in LsaWrapper.EnumerateAccountsWithUserRight when SID cannot be resolved
    - Added Grant-TokenPrivilege
    - Added Revoke-TokenPrivilege

1.3       2016-10-29    Tony Pombo
    - Minor changes to support Nano server
    - SIDs can now be specified for all account parameters
    - Script is now digitally signed

#> # Revision History

#Requires -Version 3.0
Set-StrictMode -Version 2.0

Add-Type @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
'@ # This type (PS_LSA) is used by Grant-UserRight, Revoke-UserRight, Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight, Grant-TokenPriviledge, Revoke-TokenPrivilege

function Grant-UserRight {
 <#
  .SYNOPSIS
    Assigns user rights to accounts
  .DESCRIPTION
    Assigns one or more user rights (privileges) to one or more accounts. If you specify privileges already granted to the account, they are ignored.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Right
    Name of the right to grant. More than one right may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Grant-UserRight "bilbo.baggins" SeServiceLogonRight

    Grants bilbo.baggins the "Logon as a service" right on the local computer.
  .EXAMPLE
    Grant-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC

    Grants both Edward and Karen, "Logon as a service" and "Create a token object" rights on the TESTPC system.
  .INPUTS
    String Account
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721786.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            foreach ($Priv in $Right) {
                $lsa.AddPrivilege($Acct,$Priv)
            }
        }
    }
} # Assigns user rights to accounts

function Revoke-UserRight {
 <#
  .SYNOPSIS
    Removes user rights from accounts
  .DESCRIPTION
    Removes one or more user rights (privileges) from one or more accounts. If you specify privileges not held by the account, they are ignored.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Right
    Name of the right to revoke. More than one right may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Revoke-UserRight "bilbo.baggins" SeServiceLogonRight

    Removes the "Logon as a service" right from bilbo.baggins on the local computer.
  .EXAMPLE
    Revoke-UserRight "S-1-5-21-3108507890-3520248245-2556081279-1001" SeServiceLogonRight

    Removes the "Logon as a service" right from the specified SID on the local computer.
  .EXAMPLE
    Revoke-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC

    Removes the "Logon as a service" and "Create a token object" rights from both Edward and Karen on the TESTPC system.
  .INPUTS
    String Account
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721809.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            foreach ($Priv in $Right) {
                $lsa.RemovePrivilege($Acct,$Priv)
            }
        }
    }
} # Removes user rights from accounts

function Get-UserRightsGrantedToAccount {
 <#
  .SYNOPSIS
    Gets all user rights granted to an account
  .DESCRIPTION
    Retrieves a list of all the user rights (privileges) granted to one or more accounts. The rights retrieved are those granted directly to the user account, and does not include those rights obtained as part of membership to a group.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount "bilbo.baggins"

    Returns a list of all user rights granted to bilbo.baggins on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount -Account "Edward","Karen" -Computer TESTPC

    Returns a list of user rights granted to Edward, and a list of user rights granted to Karen, on the TESTPC system.
  .INPUTS
    String Account
    String Computer
  .OUTPUTS
    String Account
    PS_LSA.Rights Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721790.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            $output = @{'Account'=$Acct; 'Right'=$lsa.EnumerateAccountPrivileges($Acct); }
            Write-Output (New-Object –Typename PSObject –Prop $output)
        }
    }
} # Gets all user rights granted to an account

function Get-AccountsWithUserRight {
 <#
  .SYNOPSIS
    Gets all accounts that are assigned a specified privilege
  .DESCRIPTION
    Retrieves a list of all accounts that hold a specified right (privilege). The accounts returned are those that hold the specified privilege directly through the user account, not as part of membership to a group.
  .PARAMETER Right
    Name of the right to query. More than one right may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-AccountsWithUserRight SeServiceLogonRight

    Returns a list of all accounts that hold the "Log on as a service" right.
  .EXAMPLE
    Get-AccountsWithUserRight -Right SeServiceLogonRight,SeDebugPrivilege -Computer TESTPC

    Returns a list of accounts that hold the "Log on as a service" right, and a list of accounts that hold the "Debug programs" right, on the TESTPC system.
  .INPUTS
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    String Account
    String Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721792.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Priv in $Right) {
            $output = @{'Account'=$lsa.EnumerateAccountsWithUserRight($Priv); 'Right'=$Priv; }
            Write-Output (New-Object –Typename PSObject –Prop $output)
        }
    }
} # Gets all accounts that are assigned a specified privilege

function Grant-TokenPrivilege {
 <#
  .SYNOPSIS
    Enables privileges in the current process token.
  .DESCRIPTION
    Enables one or more privileges for the current process token. If a privilege cannot be enabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to enable. More than one privilege may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Grant-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Enables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege) {
            try { [PS_LSA.TokenManipulator]::AddPrivilege($Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
            }
        }
    }
} # Enables privileges in the current process token

function Revoke-TokenPrivilege {
 <#
  .SYNOPSIS
    Disables privileges in the current process token.
  .DESCRIPTION
    Disables one or more privileges for the current process token. If a privilege cannot be disabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to disable. More than one privilege may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Revoke-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Disables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege) {
            try { [PS_LSA.TokenManipulator]::RemovePrivilege($Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
            }
        }
    }
} # Disables privileges in the current process token

# SIG # Begin signature block
# MIIaqAYJKoZIhvcNAQcCoIIamTCCGpUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpS3fnwqe9tuG/hiWvV/H48OJ
# BMygghXmMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggaiMIIFiqADAgECAhAN6iEsb6cnE09UybREgXi6MA0GCSqGSIb3DQEBBQUAMG8x
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xLjAsBgNVBAMTJURpZ2lDZXJ0IEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBLTEwHhcNMTMxMDI1MDAwMDAwWhcNMTYxMTAyMTIwMDAwWjBu
# MQswCQYDVQQGEwJVUzENMAsGA1UECBMET2hpbzEUMBIGA1UEBxMLQmVhdmVyY3Jl
# ZWsxHDAaBgNVBAoTE0VkaWN0IFN5c3RlbXMsIEluYy4xHDAaBgNVBAMTE0VkaWN0
# IFN5c3RlbXMsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
# 7MWJJRiWHLuX7SVHbWTXZ7hJCjlhnEdU2EpmUqM39EO+99l+0PxPjEfQyaqI/dVo
# 7Rdgua41K/1oCwW9ppCR8W+ibJQYsfX7VxT/3THHM5Dq/6C9TIGctws6X3QNAo6H
# S6HJTXOorMrYFuybB65LJlwl1W85fDeFCMhXhoASml/FGX4L40sWka2VDz6u+xj3
# hpya9rf9c4Lrq2H5kurU3Rp4MCbmbrTMAKNZV2Iooj7aPGUyPmLAzTMt59eU7gW8
# 0YHxCSrJVPuCCIxMOBqkJAXjKCbA+W0ZrsFn//Ja45pSxvDPeEr+Nbz8j4UVQiKq
# DE875maD1mR6OCjF9D+rAgMBAAGjggM5MIIDNTAfBgNVHSMEGDAWgBR7aM4pqsAX
# vkl64eU/1qf3RY81MjAdBgNVHQ4EFgQUuGdB5q1guvLKM0IvU4gsU2qWSUwwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHMGA1UdHwRsMGowM6Ax
# oC+GLWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9hc3N1cmVkLWNzLTIwMTFhLmNy
# bDAzoDGgL4YtaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL2Fzc3VyZWQtY3MtMjAx
# MWEuY3JsMIIBxAYDVR0gBIIBuzCCAbcwggGzBglghkgBhv1sAwEwggGkMDoGCCsG
# AQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRv
# cnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBm
# ACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABp
# AHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAg
# AEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAg
# AFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAg
# AHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBu
# AGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBp
# AG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMIGCBggrBgEFBQcBAQR2MHQw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBMBggrBgEFBQcw
# AoZAaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Q29kZVNpZ25pbmdDQS0xLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUA
# A4IBAQANfU4QEzjapitZj6wxGTbC6b/zr7Q6XpC2t4vnJyi7Un4+hw+ZIZ/Ttpau
# 4hrRUAX8XgWAUTktVs+HMfFPE50hBRIwSxY6Psjx91whpvN5pobqC86fadfHJf8q
# 9zQntvJlMKuX5psY69UGKjFKaCQ8Sqaxws8weKQKQZvBY/BXZz039N7joWDBBeDj
# z/H5MQuqUb0zuRDC5nC5l2hQgWHC9p17YMUd24X7vcuP9T7VGCQd2qCXgITuG9QQ
# FZ6p38AxjJQwXfonB3dj+Ae8tBlV8bET3QIsXAtfsNObpq+2nr/HRhauMCIvFwjC
# 7UFYM2CDhZWUyzSqP7/Tnf0JF4W5MIIGozCCBYugAwIBAgIQD6hJBhXXAKC+IXb9
# xextvTANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTEwMjExMTIwMDAwWhcNMjYw
# MjEwMTIwMDAwWjBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBB
# c3N1cmVkIElEIENvZGUgU2lnbmluZyBDQS0xMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAnHz5oI8KyolLU5o87BkifwzL90hE0D8ibppP+s7fxtMkkf+o
# UpPncvjxRoaUxasX9Hh/y3q+kCYcfFMv5YPnu2oFKMygFxFLGCDzt73y3Mu4hkBF
# H0/5OZjTO+tvaaRcAS6xZummuNwG3q6NYv5EJ4KpA8P+5iYLk0lx5ThtTv6AXGd3
# tdVvZmSUa7uISWjY0fR+IcHmxR7J4Ja4CZX5S56uzDG9alpCp8QFR31gK9mhXb37
# VpPvG/xy+d8+Mv3dKiwyRtpeY7zQuMtMEDX8UF+sQ0R8/oREULSMKj10DPR6i3JL
# 4Fa1E7Zj6T9OSSPnBhbwJasB+ChB5sfUZDtdqwIDAQABo4IDQzCCAz8wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIIBwwYDVR0gBIIBujCCAbYw
# ggGyBghghkgBhv1sAzCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNl
# cnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYe
# ggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYA
# aQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQA
# YQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8A
# QwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQA
# eQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAA
# bABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAA
# bwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4A
# YwBlAC4wEgYDVR0TAQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4E
# FgQUe2jOKarAF75JeuHlP9an90WPNTIwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wDQYJKoZIhvcNAQEFBQADggEBAHtyHWT/iMg6wbfp56nEh7vblJLX
# kFkz+iuH3qhbgCU/E4+bgxt8Q8TmjN85PsMV7LDaOyEleyTBcl24R5GBE0b6nD9q
# UTjetCXL8KvfxSgBVHkQRiTROA8moWGQTbq9KOY/8cSqm/baNVNPyfI902zcI+2q
# oE1nCfM6gD08+zZMkOd2pN3yOr9WNS+iTGXo4NTa0cfIkWotI083OxmUGNTVnBA8
# 1bEcGf+PyGubnviunJmWeNHNnFEVW0ImclqNCkojkkDoht4iwpM61Jtopt8pfwa5
# PA69n8SGnIJHQnEyhgmZcgl5S51xafVB/385d2TxhI2+ix6yfWijpZCxDP8xggQs
# MIIEKAIBATCBgzBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBB
# c3N1cmVkIElEIENvZGUgU2lnbmluZyBDQS0xAhAN6iEsb6cnE09UybREgXi6MAkG
# BSsOAwIaBQCgcDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0B
# CQQxFgQU5sVbXGQsOK1b8Au04DL6jwBp+DYwDQYJKoZIhvcNAQEBBQAEggEAqiSA
# hVPXtwJ76Xb+WhI6cUBEB/d39eV+453AluMTKRFHpfXqBFZ8ZFLIU94RcTDTNLWl
# mSnYEYTqHCFUNpsSb/Sh3mLgsY+qEuZEs43OsIFqPdz6wokuTc1hL5eryWT+2aVv
# HtzZ78E0e2hl4zCQDLS6E5czfXoscDF098uI/t07IoIlUf9Hmu+JI5njl9VJWgPF
# s2fBDH3Iyt6aQzXLiBiKpeo878p5GzABKOYaAmdkhG5Frj25vjrgVmPLur7bXmZr
# yPvToyB6cel6BPyvv58CTPerKtdYQ53+cHT3+95fAuoVHhEMU+ukFI4nO0AJY8wn
# yNDQ80+DBw9eTCZ/eqGCAgswggIHBgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4G
# A1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAO
# z/Q4yP6/NW4E2GqYGxpQMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZI
# hvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjEwMjkxMDU5NDJaMCMGCSqGSIb3DQEJ
# BDEWBBRKl1WuDh2YdKCoir5nzj7mCfrv/zANBgkqhkiG9w0BAQEFAASCAQBsC4zZ
# dI/RR/7Od88DSWeFI4Vqoa5Fc733A+lY+zi1E/zf9JlD96xW8O+xdLpwxY7OMxqu
# rLeGsSw8XoRy7cCVBXgivBPrDdfgue2xrBVmSLvMzEDwSBJrrfkoBWmCR/RU+eSN
# WAMCpXLhLByP2uhBwwUGdu5Tfl9HYuFhBOFHO9bPvyUZwCevaRR0NYeuYY9e6Bcx
# Ik7bg+P+5pRWAUReoWRKrYtDU6z+ZIOPZ2hs0oMNyytg2eylIrAp/uEPDx0onCG/
# 6FMt9z1UdoaL/ewPAR8VsIDUtGx9ySoCnxPv4ogw4bH38AJyDvW8xKIU45Rvt+bZ
# LR81mWebhGN4TeO3
# SIG # End signature block
