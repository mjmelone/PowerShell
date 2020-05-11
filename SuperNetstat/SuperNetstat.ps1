$TypeDefinition=@"
using System;
using System.Runtime.InteropServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

// https://msdn2.microsoft.com/en-us/library/aa366073.aspx
namespace IPHelper {

    // https://msdn2.microsoft.com/en-us/library/aa366913.aspx
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint owningPid;
    }

    // https://msdn2.microsoft.com/en-us/library/aa366921.aspx
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
     }

    // https://msdn.microsoft.com/en-us/library/aa366896
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint state;
        public uint owningPid;
    }

    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366905
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6TABLE_OWNER_PID {
       public uint dwNumEntries;
       [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
       public MIB_TCP6ROW_OWNER_PID[] table;
    }

    // https://msdn2.microsoft.com/en-us/library/aa366386.aspx
    public enum TCP_TABLE_CLASS {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    // https://msdn.microsoft.com/en-us/library/aa366896.aspx
    public enum MIB_TCP_STATE {
        MIB_TCP_STATE_CLOSED,
        MIB_TCP_STATE_LISTEN,
        MIB_TCP_STATE_SYN_SENT,
        MIB_TCP_STATE_SYN_RCVD,
        MIB_TCP_STATE_ESTAB,
        MIB_TCP_STATE_FIN_WAIT1,
        MIB_TCP_STATE_FIN_WAIT2,
        MIB_TCP_STATE_CLOSE_WAIT,
        MIB_TCP_STATE_CLOSING,
        MIB_TCP_STATE_LAST_ACK,
        MIB_TCP_STATE_TIME_WAIT,
        MIB_TCP_STATE_DELETE_TCB
    }

    public static class IPHelperAPI {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr tcpTable,
            ref int tcpTableLength,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tcpTableType,
            int reserved=0);
    }

    public class IPHelperWrapper : IDisposable {

        public const int AF_INET = 2;    // IP_v4 = System.Net.Sockets.AddressFamily.InterNetwork
        public const int AF_INET6 = 23;  // IP_v6 = System.Net.Sockets.AddressFamily.InterNetworkV6

        // Creates a new wrapper for the local machine
        public IPHelperWrapper() { }

        // Disposes of this wrapper
        public void Dispose() { GC.SuppressFinalize(this); }

        public List<MIB_TCPROW_OWNER_PID> GetAllTCPv4Connections() {
            return GetTCPConnections<MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID>(AF_INET);
        }

        public List<MIB_TCP6ROW_OWNER_PID> GetAllTCPv6Connections() {
            return GetTCPConnections<MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID>(AF_INET6);
        }

        public List<IPR> GetTCPConnections<IPR, IPT>(int ipVersion) { //IPR = Row Type, IPT = Table Type

            IPR[] tableRows;
            int buffSize = 0;
            var dwNumEntriesField = typeof(IPT).GetField("dwNumEntries");

            // how much memory do we need?
            uint ret = IPHelperAPI.GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);

            try {
                ret = IPHelperAPI.GetExtendedTcpTable(tcpTablePtr, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0) return new List<IPR>();

                // get the number of entries in the table
                IPT table = (IPT)Marshal.PtrToStructure(tcpTablePtr, typeof(IPT));
                int rowStructSize = Marshal.SizeOf(typeof(IPR));
                uint numEntries = (uint)dwNumEntriesField.GetValue(table);

                // buffer we will be returning
                tableRows = new IPR[numEntries];

                IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                for (int i = 0; i < numEntries; i++) {
                    IPR tcpRow = (IPR)Marshal.PtrToStructure(rowPtr, typeof(IPR));
                    tableRows[i] = tcpRow;
                    rowPtr = (IntPtr)((long)rowPtr + rowStructSize);   // next entry
                }
            }
            finally {
                // Free the Memory
                Marshal.FreeHGlobal(tcpTablePtr);
            }
            return tableRows != null ? tableRows.ToList() : new List<IPR>();
        }

        // Occurs on destruction of the Wrapper
        ~IPHelperWrapper() { Dispose(); }

    } // wrapper class
} // namespace
"@
Add-Type -TypeDefinition $TypeDefinition -PassThru | Out-Null

function NetStat {
  # Get services, put in a hashtable
  $hshServices = @{}
  Get-WmiObject -Namespace "root\cimv2" -Class "Win32_Service" -Filter "State='Running'" | %{
      if ($hshServices.ContainsKey($_.ProcessID)) {
          $hshServices[$_.ProcessId] += ", $($_.Name)"
      } else {
          $hshServices.Add($_.ProcessID, $_.Name)
      }
  }

  $hshProcesses = @{}

  Get-Process | %{
      $hshProcesses.add([uint32]$_.ID, $_)
  }

  $x=New-Object IPHelper.IPHelperWrapper
  $y = [array] $x.GetAllTCPv4Connections()
  $y += $x.GetAllTCPv6Connections()

  $StateList=@("UNKNOWN","CLOSED","LISTEN","SYN-SENT","SYN-RECEIVED","ESTABLISHED","FIN-WAIT-1","FIN-WAIT-2","CLOSE-WAIT","CLOSING","LAST-ACK","TIME-WAIT","DELETE-TCB")

  $arrResults = New-Object System.Collections.Generic.List[PSObject]
  $y | %{

    $objOutput=New-Object -TypeName PSObject
    # Determine if this is IPv4 or IPv6
    if ($_.LocalAddr.count -eq 1) {
        # IPv4
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "LocalAddress" -Value (New-Object System.Net.IPAddress $_.localAddr).IPAddressToString
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "RemoteAddress" -Value (New-Object System.Net.IPAddress $_.remoteAddr).IPAddressToString
    } else {
        # IPv6
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "LocalAddress" -Value (New-Object System.Net.IPAddress -ArgumentList @($_.localAddr, 0)).IPAddressToString
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "RemoteAddress" -Value (New-Object System.Net.IPAddress -ArgumentList @($_.remoteAddr, 0)).IPAddressToString        
    }

    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "LocalPort" -Value ($_.localPort[1]+($_.localPort[0]*0x100)+($_.localPort[3]*0x1000)+($_.localPort[2]*0x10000))
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "RemotePort" -Value ($_.remotePort[1]+($_.remotePort[0]*0x100)+($_.remotePort[3]*0x1000)+($_.remotePort[2]*0x10000)) 
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "PID" -Value $_.owningPid
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessName" -Value $hshProcesses[$_.owningPid].ProcessName
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessPath" -Value $hshProcesses[$_.owningPid].Path
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessCompany" -Value $hshProcesses[$_.owningPid].Company
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessFileVersion" -Value $hshProcesses[$_.owningPid].FileVersion
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessProductVersion" -Value $hshProcesses[$_.owningPid].ProductVersion
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessProductDescription" -Value $hshProcesses[$_.owningPid].Description
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessProduct" -Value $hshProcesses[$_.owningPid].Product
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessStartTime" -Value $hshProcesses[$_.owningPid].StartTime
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "StateValue" -Value $_.state
    Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "State" -Value $StateList[$_.state]

    if ($hshServices.ContainsKey($_.owningPID)) {
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ServiceName" -Value $hshServices[$_.owningPID]
    } else {
        Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ServiceName" -Value $Null
    }
    $arrResults.add($objOutput)
  }

  return $arrResults
}

NetStat

# This Sample Code is provided for the purpose of illustration only and is not intended to be used 
# in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" 
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, 
# royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code 
# form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to 
# market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright 
# notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold 
# harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ 
# fees, that arise or result from the use or distribution of the Sample Code.

# This sample script is not supported under any Microsoft standard support program or service. 
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
# all implied warranties including, without limitation, any implied warranties of merchantability 
# or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
# the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
# or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
# damages whatsoever (including, without limitation, damages for loss of business profits, business 
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
# inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
# possibility of such damages 
