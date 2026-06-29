<#
.SYNOPSIS
    Pre-seeds Log Analytics custom log tables for LAB05 - Monitor and Analyze Compute Workloads.

.DESCRIPTION
    Called by the ARM template Custom Script Extension on ops-vm-01 during lab provisioning.
    Uses the Log Analytics HTTP Data Collector API to insert sample records into two custom tables:
      - SecurityEvents_CL  : Simulated Windows Security event log entries (failed logins, Event ID 4625)
      - AppServiceHTTPLogs_CL : Simulated App Service HTTP access log entries (404 errors)

    All string fields use clearly custom names to ensure the _s type suffix is applied
    consistently on ingestion. Numeric fields receive the _d suffix.

    Field mapping:
      SecurityEvents_CL  : EventID_d, LogonType_d, HostName_s, TargetAccount_s, SourceIP_s, LogonDesc_s
      AppServiceHTTPLogs_CL : ScStatus_d, TimeTaken_d, HttpMethod_s, RequestPath_s, HostHeader_s

.PARAMETER WorkspaceId
    The Log Analytics workspace GUID (customerId). Passed by the ARM template at deploy time.

.PARAMETER WorkspaceKey
    The Log Analytics workspace primary shared key. Passed by the ARM template via protectedSettings.

.NOTES
    Repository : ps-mike-boorman/test-deployment-handsonlab
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
        'Authorization' = 'SharedKey ' + $WorkspaceId + ':' + $signature
        'Log-Type'      = $LogType
        'x-ms-date'     = $rfc1123Date
    }

    try {
        $null = Invoke-RestMethod -Uri $uri -Method POST -ContentType $contentType -Headers $headers -Body $Body
        Write-Output ('[' + $LogType + '] Seeded successfully.')
    }
    catch {
        Write-Warning ('[' + $LogType + '] Seed failed: ' + $_)
    }
}

# ---------------------------------------------------------------------------
# SecurityEvents_CL
# Simulates Windows Security event log entries. Field names are deliberately
# non-generic to ensure the _s type suffix is applied reliably on ingestion.
# EventID and LogonType are numeric and receive the _d suffix.
# ---------------------------------------------------------------------------
$securityEvents = @(
    @{ HostName = 'ops-vm-01'; TargetAccount = 'UNKNOWN\administrator'; EventID = 4625; LogonDesc = 'An account failed to log on'; LogonType = 10; SourceIP = '203.0.113.42' },
    @{ HostName = 'ops-vm-01'; TargetAccount = 'UNKNOWN\admin';         EventID = 4625; LogonDesc = 'An account failed to log on'; LogonType = 10; SourceIP = '198.51.100.17' },
    @{ HostName = 'ops-vm-01'; TargetAccount = 'UNKNOWN\root';          EventID = 4625; LogonDesc = 'An account failed to log on'; LogonType = 10; SourceIP = '203.0.113.88' },
    @{ HostName = 'ops-vm-01'; TargetAccount = 'UNKNOWN\testuser';      EventID = 4625; LogonDesc = 'An account failed to log on'; LogonType = 10; SourceIP = '198.51.100.23' },
    @{ HostName = 'ops-vm-01'; TargetAccount = 'opsadmin';              EventID = 4624; LogonDesc = 'An account was successfully logged on'; LogonType = 3; SourceIP = '10.0.0.5' },
    @{ HostName = 'ops-vm-01'; TargetAccount = 'UNKNOWN\sysadmin';      EventID = 4625; LogonDesc = 'An account failed to log on'; LogonType = 10; SourceIP = '203.0.113.99' }
) | ConvertTo-Json

Send-LogData -WorkspaceId $WorkspaceId -WorkspaceKey $WorkspaceKey -Body $securityEvents -LogType 'SecurityEvents'

# ---------------------------------------------------------------------------
# AppServiceHTTPLogs_CL
# Simulates App Service HTTP access log entries. ScStatus and TimeTaken are
# numeric (_d suffix). HttpMethod, RequestPath, and HostHeader are strings
# (_s suffix).
# ---------------------------------------------------------------------------
$httpLogs = @(
    @{ HttpMethod = 'GET';    RequestPath = '/api/users/9999';       ScStatus = 404; TimeTaken = 245; HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'GET';    RequestPath = '/products/deleted-item'; ScStatus = 404; TimeTaken = 198; HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'POST';   RequestPath = '/api/orders/0';          ScStatus = 404; TimeTaken = 312; HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'GET';    RequestPath = '/images/logo-old.png';   ScStatus = 404; TimeTaken = 156; HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'GET';    RequestPath = '/api/users/1';           ScStatus = 200; TimeTaken = 89;  HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'GET';    RequestPath = '/about/old-page';        ScStatus = 404; TimeTaken = 201; HostHeader = 'ops-webapp.azurewebsites.net' },
    @{ HttpMethod = 'DELETE'; RequestPath = '/api/items/xyz';         ScStatus = 404; TimeTaken = 178; HostHeader = 'ops-webapp.azurewebsites.net' }
) | ConvertTo-Json

Send-LogData -WorkspaceId $WorkspaceId -WorkspaceKey $WorkspaceKey -Body $httpLogs -LogType 'AppServiceHTTPLogs'

Write-Output 'Log seeding complete.'
