<#<#
.SYNOPSIS
This function checks the state of components involved in delivery of Microsoft Defender for Endpoint

.EXAMPLE
Get-MDEState

.NOTES
Created by Michael Melone, Principal Program Manager, Microsoft 365 Defender
#>#>
Function Get-MDEState
{
    Add-Type '
        public class TelemetryState
        {
            public System.DateTimeOffset? ReportTime;
            public int SuccessfulConnections;
            public int FailedConnections;
            public string LastHttpError;
            public bool ProxySettingDetected;
            public int SslCertValidationFailure;
            public string LastSslCertFailure;
        }
        public class CommandAndControlState
        {
            public System.DateTimeOffset? LastNormalUploadTime;
            public System.DateTimeOffset? LastRealtimeUploadTime;
            public int SuccessfulConnections;
            public int AttemptedConnections;
            public int FailedConnections;
            public string LastHttpErrorCode;
            public string Url;
            public string OrgId;
            public bool IsOnboarded;
        }
        public class DefenderServiceState
        {
            public string SenseServiceState;
            public string SenseServiceStartupType;
            public string UtcServiceState;
            public string UtcServiceStartupType;
            public string DefenderAvServiceState;
            public string DefenderAvServiceStartupType;
            public string FirewallServiceState;
            public string FirewallServiceStartupType;
            public string WnsServiceState;
            public string WnsServiceStartupType;
        }
        public class MDEHealthReport
        {
            // Command and Control State
            public System.DateTimeOffset C2LastNormalUploadTime;
            public System.DateTimeOffset C2LastRealtimeUploadTime;
            public int C2SuccessfulConnections;
            public int C2AttemptedConnections;
            public int C2FailedConnections;
            public string C2LastHttpErrorCode;
            public string C2Url;
            public string OrgId;
            public bool IsOnboarded;

            // Telemetry State
            public System.DateTimeOffset TelemetryReportTime;
            public int TelemetrySuccessfulConnections;
            public int TelemetryFailedConnections;
            public string TelemetryLastHttpError;
            public bool TelemetryProxySettingDetected;
            public int TelemetrySslCertValidationFailure;
            public string TelemetryLastSslCertFailure;

            // Service State
            public string SenseServiceState;
            public string SenseServiceStartupType;
            public string UtcServiceState;
            public string UtcServiceStartupType;
            public string DefenderAvServiceState;
            public string DefenderAvServiceStartupType;
            public string FirewallServiceState;
            public string FirewallServiceStartupType;
            public string WnsServiceState;
            public string WnsServiceStartupType;

            // MpComputerStatus
            public string AMEngineVersion;
            public string AMProductVersion;
            public string AMRunningMode;
            public bool AMServiceEnabled;
            public string AMServiceVersion;
            public bool AntispywareEnabled;
            public string AntispywareSignatureAge;
            public System.DateTimeOffset? AntispywareSignatureLastUpdated;
            public string AntispywareSignatureVersion;
            public string AntivirusEnabled;
            public string AntivirusSignatureAge;
            public System.DateTimeOffset? AntivirusSignatureLastUpdated;
            public string AntivirusSignatureVersion;
            public bool BehaviorMonitoringEnabled;
            public string ComputerID;
            public string ComputerState;
            public string FullScanAge;
            public System.DateTimeOffset? FullScanEndTime;
            public System.DateTimeOffset? FullScanStartTime;
            public bool IoavProtectionEnabled;
            public bool IsTamperProtected;
            public bool IsVirtualMachine;
            public byte LastFullScanSource;
            public byte LastQuickScanSource;
            public bool NISEnabled;
            public string NISEngineVersion;
            public string NISSignatureAge;
            public System.DateTimeOffset? NISSignatureLastUpdated;
            public string NISSignatureVersion;
            public bool OnAccessProtectionEnabled;
            public string QuickScanAge;
            public System.DateTimeOffset? QuickScanEndTime;
            public System.DateTimeOffset? QuickScanStartTime;
            public bool RealTimeProtectionEnabled;
            public byte RealTimeScanDirection;
        }'
    function Get-CommandAndControlState
    {

        $result = New-Object 'CommandAndControlState'

        $LatestConnectionAttemptReport = Get-WinEvent -Path (Join-Path $env:windir "system32\Winevt\logs\Microsoft-Windows-SENSE%4Operational.evtx") |
            ?{$_.id -in @("4","67")} |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1

        if ($LatestConnectionAttemptReport)
        {      
            if ($LatestConnectionAttemptReport.Id -eq "4")
            {
                $Result.SuccessfulConnections = $LatestConnectionAttemptReport.properties[0].value
                $Result.AttemptedConnections = $Result.SuccessfulConnections
                $Result.FailedConnections = 0
                $Result.Url = $LatestConnectionAttemptReport.properties[1].value
            } else {
                $Result.AttemptedConnections = $LatestConnectionAttemptReport.properties[0].value
                $Result.FailedConnections = $LatestConnectionAttemptReport.properties[1].value
                $Result.SuccessfulConnections = $LatestConnectionAttemptReport.properties[2].value
                $Result.Url = $LatestConnectionAttemptReport.properties[3].value
                $Result.LastHTTPErrorCode = $LatestConnectionAttemptReport.properties[4].value
            }
        } 
        
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")
        {
            $Result.OrgId = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OrgId)
            $Result.IsOnboarded = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OnboardingState)
        }

        # Update the lsdy upload times and error codes with registry value when possible
        $OSBuild = ([System.Environment]::OSVersion).Version.build
        if ($OSBuild -eq 14393) {
            $result.LastNormalUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Name LastNormalUploadTime))
            $result.LastRealtimeUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Name LastRealTimeUploadTime))
            $Result.LastHTTPErrorCode = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Name LastInvalidHttpCode)
        } elseif ($OSBuild -le 17134) {
            $result.LastNormalUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Name LastNormalUploadTime))
            $result.LastRealtimeUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Name LastRealTimeUploadTime))
            $Result.LastHTTPErrorCode = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Name LastInvalidHttpCode)
        } else {
            $result.LastNormalUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Name LastSuccessfulNormalUploadTime))
            $result.LastRealtimeUploadTime = [DateTimeOffset]::FromFileTime((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Name LastSuccessfulRealtimeUploadTime))
            $Result.LastHTTPErrorCode = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib\HeartBeats\Seville" -Name LastInvalidHttpCode)
        }

        return $result
    }

    function Get-TelemetryState {

        $result = New-Object 'TelemetryState'

        $LastEvent = Get-WinEvent -Path (Join-Path $env:windir "system32\Winevt\logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx") |
            ?{$_.id -in @("27","28","29")} | 
            Sort-Object TimeCreated -Descending | 
            Select-Object -First 1

        switch ($LastEvent.Id)
        {
            "27"{
                $result.ReportTime = $LastEvent.TimeCreated
                $result.SuccessfulConnections = $LastEvent.properties[1].value
                $result.FailedConnections = 0
            }
            "28"{
                $result.ReportTime = $LastEvent.TimeCreated
                $result.SuccessfulConnections = $LastEvent.properties[4].value
                $result.FailedConnections = $LastEvent.properties[5].value
                $result.LastHttpError = $LastEvent.properties[6].value
            }
            "29"{
                $result.ReportTime = $LastEvent.TimeCreated
                $result.FailedConnections = $LastEvent.properties[4].value
                $result.LastHttpError = $LastEvent.properties[5].value
                $result.ProxySettingDetected = $LastEvent.properties[6].value -eq 'true'
                $result.SslCertValidationFailure = $LastEvent.properties[7].value
                $result.LastSslCertFailure = $LastEvent.properties[8].value
            }
        }

        return $result
    }

    function Get-DefenderServiceState
    {

        $result = New-Object DefenderServiceState

        $SenseService = (Get-Service -Name Sense)
        $UTCService = (Get-Service -Name DiagTrack)
        $DefenderService = (Get-Service -Name WinDefend)
        #$WlidService = (Get-Service -Name wlidsvc)
        $FirewallService = (Get-Service -Name mpssvc)
        $WnsService = (Get-Service -Name WpnService)

        $result.SenseServiceState = $SenseService.Status
        $result.SenseServiceStartupType = $SenseService.StartType

        $result.UtcServiceState = $UTCService.Status
        $result.UtcServiceStartupType = $UTCService.StartType

        $result.DefenderAvServiceState = $DefenderService.Status
        $result.DefenderAvServiceStartupType = $DefenderService.StartType

        $result.FirewallServiceState = $FirewallService.Status
        $result.FirewallServiceStartupType = $FirewallService.StartType

        $result.WnsServiceState = $WnsService.Status
        $result.WnsServiceStartupType = $WnsService.StartType

        return $result
    }

    $output = New-Object MDEHealthReport

    $C2State = Get-CommandAndControlState
    $TelemetryState = Get-TelemetryState
    $ServiceState = Get-DefenderServiceState
    $MDAVState = Get-MpComputerStatus

    # Command and Control State
    $output.C2LastNormalUploadTime = $C2State.LastNormalUploadTime
    $output.C2LastRealtimeUploadTime = $C2State.LastRealTimeUploadTime
    $output.C2SuccessfulConnections = $C2State.SuccessfulConnections
    $output.C2AttemptedConnections = $C2State.AttemptedConnections
    $output.C2FailedConnections = $C2State.FailedConnections
    $output.C2LastHttpErrorCode = $C2State.LastHttpErrorCode
    $output.C2Url = $C2State.Url
    $output.OrgId = $C2State.OrgId
    $output.IsOnboarded = $C2State.IsOnboarded

    # Telemetry State
    $output.TelemetryReportTime = $TelemetryState.ReportTime
    $output.TelemetrySuccessfulConnections = $TelemetryState.SuccessfulConnections
    $output.TelemetryFailedConnections = $TelemetryState.FailedConnections
    $output.TelemetryLastHttpError = $TelemetryState.LastHttpError
    $output.TelemetryProxySettingDetected = $TelemetryState.ProxySettingDetected
    $output.TelemetrySslCertValidationFailure = $TelemetryState.SslCertValidationFailure
    $output.TelemetryLastSslCertFailure = $TelemetryState.LastSslCertFailure

    # Service State
    $output.SenseServiceState = $ServiceState.SenseServiceState
    $output.SenseServiceStartupType = $ServiceState.SenseServiceStartupType
    $output.UtcServiceState = $ServiceState.UtcServiceState
    $output.UtcServiceStartupType = $ServiceState.UtcServiceStartupType
    $output.DefenderAvServiceState = $ServiceState.DefenderAvServiceState
    $output.DefenderAvServiceStartupType = $ServiceState.DefenderAvServiceStartupType
    $output.FirewallServiceState = $ServiceState.FirewallServiceState
    $output.FirewallServiceStartupType = $ServiceState.FirewallServiceStartupType
    $output.WnsServiceState = $ServiceState.WnsServiceState
    $output.WnsServiceStartupType = $ServiceState.WnsServiceStartupType

    # MpComputerStatus
    $output.AMEngineVersion = $MDAVState.AMEngineVersion
    $output.AMProductVersion = $MDAVState.AMProductVersion
    $output.AMRunningMode = $MDAVState.AMRunningMode
    $output.AMServiceEnabled = $MDAVState.AMServiceEnabled
    $output.AMServiceVersion = $MDAVState.AMServiceVersion
    $output.AntispywareEnabled = $MDAVState.AntispywareEnabled
    $output.AntispywareSignatureAge = $MDAVState.AntispywareSignatureAge
    $output.AntispywareSignatureLastUpdated = $MDAVState.AntispywareSignatureLastUpdated
    $output.AntispywareSignatureVersion = $MDAVState.AntispywareSignatureVersion
    $output.AntivirusEnabled = $MDAVState.AntivirusEnabled
    $output.AntivirusSignatureAge = $MDAVState.AntivirusSignatureAge
    $output.AntivirusSignatureLastUpdated = $MDAVState.AntivirusSignatureLastUpdated
    $output.AntivirusSignatureVersion = $MDAVState.AntivirusSignatureVersion
    $output.BehaviorMonitoringEnabled = $MDAVState.BehaviorMonitorEnabled
    $output.ComputerID = $MDAVState.ComputerID
    $output.ComputerState = $MDAVState.ComputerState
    $output.FullScanAge = $MDAVState.FullScanAge
    $output.FullScanEndTime = $MDAVState.FullScanEndTime
    $output.FullScanStartTime = $MDAVState.FullScanStartTime
    $output.IoavProtectionEnabled = $MDAVState.IoavProtectionEnabled
    $output.IsTamperProtected = $MDAVState.IsTamperProtected
    $output.IsVirtualMachine = $MDAVState.IsVirtualMachine
    $output.LastFullScanSource = $MDAVState.LastFullScanSource
    $output.LastQuickScanSource = $MDAVState.LastQuickScanSource
    $output.NISEnabled = $MDAVState.NISEnabled
    $output.NISEngineVersion = $MDAVState.NISEngineVersion
    $output.NISSignatureAge = $MDAVState.NISSignatureAge
    $output.NISSignatureLastUpdated = $MDAVState.NISSignatureLastUpdated
    $output.NISSignatureVersion = $MDAVState.NISSignatureVersion
    $output.OnAccessProtectionEnabled = $MDAVState.OnAccessProtectionEnabled
    $output.QuickScanAge = $MDAVState.QuickScanAge
    $output.QuickScanEndTime = $MDAVState.QuickScanEndTime
    $output.QuickScanStartTime = $MDAVState.QuickScanStartTime
    $output.RealTimeProtectionEnabled = $MDAVState.RealTimeProtectionEnabled
    $output.RealTimeScanDirection = $MDAVState.RealTimeScanDirection

    return $output
}

Get-MDEState
