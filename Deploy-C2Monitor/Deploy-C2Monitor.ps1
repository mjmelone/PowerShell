<#
	Deploy-C2Monitor
	by Michael Melone, Microsoft

	.SYNOPSIS
	This script will monitor for inbound traffic of a specified type and create events when
	traffic matching the pattern is detected.  Connections will be accepted, logged to the 
	event log, and immediately terminated.

	.DESCRIPTION
	Deploy-C2Monitor will open ports on a computer and listen for incoming connections.  When
	an incoming connection is discovered, details about that connection will be logged in an
	event log named C2-Monitor.

	.PARAMETER IPAddress
	If specified, this will listen only on the IP address specified.  If not specified, the
	script will listen on all IP addresses.

	.PARAMETER TCPPort
	This is a list of TCP ports to listen for connections on.

	.EXAMPLE
	To monitor port 12345 use the following command

	Deploy-C2Monitor -TCPPort 12345

	.EXAMPLE
	To monitor ports 10, 12, and 13 use the following command

	Deploy-C2Monitor -TCPPort 10, 12, 13

	.EXAMPLE
	To monitor port 10000 on IP address 10.1.1.1 use the following command

	Deploy-C2Monitor -IPAddress '10.1.1.1' -TCPPort 10000
#>

param(
	[ValidateScript({[System.Net.IPAddress]::Parse($_)})]
	$IPAddress,
	[parameter(mandatory=$True)]
	[ValidateRange(1-65535)]
	[int[]] $TCPPort
)

# Write log entry that the program is starting
$logC2Monitor.WriteEvent((New-Object System.Diagnostics.EventInstance(1,2,[system.diagnostics.EventLogEntryType]::Information)), "C2 Monitor is starting")

#Add the GetAsyncKeyState function 
try {
	[kbdUtil.NativeInterop] | Out-Null
} catch {
	Add-Type -MemberDefinition '
    [DllImport("User32")]
    public static extern short GetAsyncKeyState(int vKey);' -Name NativeInterop -Namespace KbdUtil
}

# Set constants for ctrl and Q
$VK_CONTROL = 0x11
$Q_KEY = 0x51

# Determine if there is an eventlog for the C2 Monitor already
if ([system.diagnostics.EventLog]::Exists('C2-Monitor')) {
	$logC2Monitor = New-Object System.Diagnostics.EventLog 'C2-Monitor'
} else {
	$logC2Monitor = New-EventLog -LogName 'C2-Monitor' -Source 'C2-Monitor'
}

$logC2Monitor.Source = 'C2-Monitor'

if ($IPAddress) {
	# Listen on a specific IP
	$ipListening = [System.Net.IPAddress]::Parse($IPAddress)
} else {
	# Listen on all IPs
	$ipListening = [system.net.ipaddress]::Any
}

$lstTCPListeners = New-Object System.Collections.Generic.List[System.Net.Sockets.TCPListener]

# Create a new TCP endpoint for each requested port
foreach ($intPort in $TCPPort) {
	# Create a new TcpListener
	New-Object System.Net.Sockets.TcpListener -argumentlist $ipListening,$intPort | %{
		# Add the listener to the list
		$lstTCPListeners.add($_)
		# Start the listener
		try {
			$_.Start()
		} catch {
			# We failed to open this port
			$logC2Monitor.WriteEvent((New-Object System.Diagnostics.EventInstance(1,1000,[system.diagnostics.EventLogEntryType]::Error)), "An error occurred while trying to open a listener on TCP port $intPort.")
			Write-Warning "Unable to open a connection on TCP port $intPort.  Please ensure that this port is not in use."
		}
	}
}

Write-Host "Monitor is active for the following ports"
Write-Host "TCP: " -NoNewline
$TCPPort | %{
	Write-host "$_ " -NoNewline
}
Write-Host
Write-Host "To stop monitoring, press Ctrl+Q to quit."

while (([KbdUtil.NativeInterop]::GetAsyncKeyState($VK_CONTROL) -band 0x8000) -eq 0 -or 
       ([KbdUtil.NativeInterop]::GetAsyncKeyState($Q_KEY) -band 0x8000) -eq 0)  {

	# Iterate through each TCPListener
	$lstTCPListeners.GetEnumerator() | %{
		# Determine if we have pending connections waiting to be accepted
		if ($_.Pending()) {

			# We have a pending connection.  Accept it and log it.
			$_.AcceptTcpClient() | %{
				$tcpClient = $_.Client

				# Try to resolve the address using reverse DNS
				$dnsClient = [system.net.dns]::GetHostEntry($tcpClient.RemoteEndpoint.Address)
				
				#Write the event
				$logC2Monitor.WriteEvent((New-Object System.Diagnostics.EventInstance(1,1,[system.diagnostics.EventLogEntryType]::Warning)),
					  @(
						"A TCP connection was made to the following monitored port.

						Server IP Address: $($tcpClient.LocalEndpoint.Address)
						Server Port: $($tcpClient.LocalEndpoint.Port)
						Client DNS Record: $($dnsClient.HostName)
						Client IP Address: $($tcpClient.RemoteEndpoint.Address)
						Client Port: $($tcpClient.RemoteEndpoint.Port)
						Protocol: TCP",
						$tcpClient.LocalEndpoint.Address,
						$tcpClient.LocalEndpoint.Port,
						$dnsClient.HostName,
						$tcpClient.RemoteEndpoint.Address,
						$tcpClient.RemoteEndpoint.Port,
						'TCP'
					)
				)
				
				# Close the port
				$_.Close()
				$_.Dispose()
			}
		}
	}
}

# Write log entry that the program is closing
$logC2Monitor.WriteEvent((New-Object System.Diagnostics.EventInstance(1,2,[system.diagnostics.EventLogEntryType]::Information)), "C2 Monitor is stopping")

# Close all of our open ports
$lstTCPListeners.GetEnumerator() | %{
	$_.stop()
}

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
