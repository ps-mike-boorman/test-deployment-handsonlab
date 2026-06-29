<#
.SYNOPSIS
    Pre-seeds Log Analytics custom log tables for LAB05 - Monitor and Analyze Compute Workloads.

.DESCRIPTION
    Called by the ARM template Custom Script Extension on ops-vm-01 during lab provisioning.
    Uses the Log Analytics HTTP Data Collector API to insert sample records into two custom tables:
      - SecurityEvents_CL  : Simulated Windows Security event log entries (failed logins, Event ID 4625)
      - AppServiceHTTPLogs_CL : Simulated App Service HTTP access log entries (404 errors)

    Field names in custom tables receive a type suffix on ingestion:
      - Numeric fields  -> _d  (e.g., EventID_d, ScStatus_d, TimeTaken_d)
      - String fields   -> _s  (e.g., Computer_s, Account_s, CsUriStem_s)
      - TimeGenerated is a reserved field and receives no suffix.

.PARAMETER WorkspaceId
    The Log Analytics workspace GUID (customerId). Passed by the ARM template at deploy time.

.PARAMETER WorkspaceKey
    The Log Analytics workspace primary shared key. Passed by the ARM template via protectedSettings.

.NOTES
    Repository : ps-mike-boorman/azure-compute-labs
    Path       : lab05-monitor/seed-logs.ps1
    Lab        : LAB05 - Monitor and Analyze Compute Workloads in Azure
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Send-LogData {
    <#
    .SYNOPSIS
        Posts a JSON array to the Log Analytics HTTP Data Collector API.
    .DESCRIPTION
        Builds the required HMAC-SHA256 Authorization header and sends the payload
        to the workspace REST endpoint. The LogType value becomes the table name
        with a _CL suffix appended automatically by the service.
    #>
    param (
        [string]$WorkspaceId,
        [string]$WorkspaceKey,
        [string]$Body,
        [string]$LogType
    )

    $method      = 'POST'
    $contentType = 'application/json'
    $resource    = '/api/logs'
    $rfc1123Date = [DateTime]::UtcNow.ToString('r')
    $newline     = [char]10

    $contentLength = ([System.Text.Encoding]::UTF8.GetBytes($Body)).Length
    $stringToHash  = $method + $newline +
                     $contentLength + $newline +
                     $contentType + $newline +
                     'x-ms-date:' + $rfc1123Date + $newline +
                     $resource

    $keyBytes  = [System.Convert]::FromBase64String($WorkspaceKey)
    $hmac      = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key  = $keyBytes
    $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToHash))
    $signature = [System.Convert]::ToBase64String($hashBytes)

    $uri     = 'https://' + $WorkspaceId + '.ods.opinsights.azure.com' + $resource + '?api-version=2016-04-01'
    $headers = @{
        'Authorization'        = 'SharedKey ' + $WorkspaceId + ':' + $signature
        'Log-Type'             = $LogType
        'x-ms-date'            = $rfc1123Date
        'time-generated-field' = 'TimeGenerated'
    }

    try {
        $null = Invoke-RestMethod -Uri $uri -Method POST -ContentType $contentType -Headers $headers -Body $Body
        Write-Output "[$LogType] Seeded successfully."
    }
    catch {
        Write-Warning "[$LogType] Seed failed: $_"
    }
}

$now = [DateTime]::UtcNow

# ---------------------------------------------------------------------------
# SecurityEvents_CL
# Simulates Windows Security event log entries that Azure Monitor Agent would
# route to the SecurityEvent table in a production environment. Includes five
# failed login attempts (Event ID 4625) from external IPs and one successful
# internal logon (Event ID 4624) for contrast.
# ---------------------------------------------------------------------------
$securityEvents = @(
    @{
        TimeGenerated = $now.AddMinutes(-55).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'UNKNOWN\administrator'
        EventID       = 4625
        Activity      = 'An account failed to log on'
        LogonType     = 10
        IpAddress     = '203.0.113.42'
    },
    @{
        TimeGenerated = $now.AddMinutes(-50).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'UNKNOWN\admin'
        EventID       = 4625
        Activity      = 'An account failed to log on'
        LogonType     = 10
        IpAddress     = '198.51.100.17'
    },
    @{
        TimeGenerated = $now.AddMinutes(-45).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'UNKNOWN\root'
        EventID       = 4625
        Activity      = 'An account failed to log on'
        LogonType     = 10
        IpAddress     = '203.0.113.88'
    },
    @{
        TimeGenerated = $now.AddMinutes(-40).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'UNKNOWN\testuser'
        EventID       = 4625
        Activity      = 'An account failed to log on'
        LogonType     = 10
        IpAddress     = '198.51.100.23'
    },
    @{
        TimeGenerated = $now.AddMinutes(-35).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'opsadmin'
        EventID       = 4624
        Activity      = 'An account was successfully logged on'
        LogonType     = 3
        IpAddress     = '10.0.0.5'
    },
    @{
        TimeGenerated = $now.AddMinutes(-30).ToString('o')
        Computer      = 'ops-vm-01'
        Account       = 'UNKNOWN\sysadmin'
        EventID       = 4625
        Activity      = 'An account failed to log on'
        LogonType     = 10
        IpAddress     = '203.0.113.99'
    }
) | ConvertTo-Json

Send-LogData -WorkspaceId $WorkspaceId -WorkspaceKey $WorkspaceKey -Body $securityEvents -LogType 'SecurityEvents'

# ---------------------------------------------------------------------------
# AppServiceHTTPLogs_CL
# Simulates App Service HTTP access log entries that App Service diagnostic
# settings would route to the AppServiceHTTPLogs table in a production
# environment. Includes five 404 responses across various paths and one 200
# for contrast.
# ---------------------------------------------------------------------------
$httpLogs = @(
    @{
        TimeGenerated = $now.AddMinutes(-62).ToString('o')
        CsMethod      = 'GET'
        CsUriStem     = '/api/users/9999'
        ScStatus      = 404
        TimeTaken     = 245
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-57).ToString('o')
        CsMethod      = 'GET'
        CsUriStem     = '/products/deleted-item'
        ScStatus      = 404
        TimeTaken     = 198
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-52).ToString('o')
        CsMethod      = 'POST'
        CsUriStem     = '/api/orders/0'
        ScStatus      = 404
        TimeTaken     = 312
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-47).ToString('o')
        CsMethod      = 'GET'
        CsUriStem     = '/images/logo-old.png'
        ScStatus      = 404
        TimeTaken     = 156
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-42).ToString('o')
        CsMethod      = 'GET'
        CsUriStem     = '/api/users/1'
        ScStatus      = 200
        TimeTaken     = 89
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-37).ToString('o')
        CsMethod      = 'GET'
        CsUriStem     = '/about/old-page'
        ScStatus      = 404
        TimeTaken     = 201
        CsHost        = 'ops-webapp.azurewebsites.net'
    },
    @{
        TimeGenerated = $now.AddMinutes(-32).ToString('o')
        CsMethod      = 'DELETE'
        CsUriStem     = '/api/items/xyz'
        ScStatus      = 404
        TimeTaken     = 178
        CsHost        = 'ops-webapp.azurewebsites.net'
    }
) | ConvertTo-Json

Send-LogData -WorkspaceId $WorkspaceId -WorkspaceKey $WorkspaceKey -Body $httpLogs -LogType 'AppServiceHTTPLogs'

Write-Output 'Log seeding complete.'
