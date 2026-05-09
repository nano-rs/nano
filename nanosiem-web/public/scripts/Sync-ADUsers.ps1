<#
.SYNOPSIS
    Syncs Active Directory users to NanoSIEM identity enrichment.

.DESCRIPTION
    Queries AD for user accounts, streams results in pages, and pushes
    each batch to the NanoSIEM identity provider API. Only fetches the
    specific attributes needed for enrichment — no full attribute dumps.

    Safe for large directories (100k+ users). Memory usage stays flat
    regardless of directory size.

.PARAMETER ApiUrl
    Base URL of your NanoSIEM instance (e.g. https://siem.corp.local)

.PARAMETER Token
    Collector token from Settings > Enrichments > Identity > Active Directory

.PARAMETER ProviderId
    Identity provider ID (default: active_directory)

.PARAMETER BatchSize
    Users per API push (default: 200). Lower if you hit request size limits.

.PARAMETER SearchBase
    AD search base DN. Defaults to the domain root.

.PARAMETER Filter
    AD user filter. Default: all user accounts (excludes computer accounts).

.PARAMETER IncludeDisabled
    Include disabled accounts (default: only enabled accounts)

.EXAMPLE
    .\Sync-ADUsers.ps1 -ApiUrl "https://siem.corp.local" -Token "abc123..."

.EXAMPLE
    .\Sync-ADUsers.ps1 -ApiUrl "https://siem.corp.local" -Token "abc123..." -IncludeDisabled -SearchBase "OU=Users,DC=corp,DC=local"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$ProviderId = "active_directory",

    [int]$BatchSize = 200,

    [string]$SearchBase,

    [string]$Filter,

    [switch]$IncludeDisabled
)

$ErrorActionPreference = "Stop"

# ── Verify AD module ──────────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory

# ── Only the attributes we need ───────────────────────────────────────────────
# This is critical: fetching all attributes (*) is what kills large-directory
# exports. We request only the 18 fields NanoSIEM uses for enrichment.
$ADProperties = @(
    "SamAccountName"
    "UserPrincipalName"
    "Mail"
    "DisplayName"
    "GivenName"
    "Surname"
    "Department"
    "Title"
    "Manager"
    "Company"
    "Office"
    "City"
    "Country"
    "MemberOf"
    "Enabled"
    "telephoneNumber"
    "EmployeeID"
    "EmployeeType"
    "LastLogonDate"
    "WhenCreated"
)

# ── Build the LDAP filter ─────────────────────────────────────────────────────
if ($Filter) {
    $ldapFilter = $Filter
} elseif ($IncludeDisabled) {
    $ldapFilter = "(&(objectCategory=person)(objectClass=user))"
} else {
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
}

# ── Query parameters ──────────────────────────────────────────────────────────
$getParams = @{
    LDAPFilter  = $ldapFilter
    Properties  = $ADProperties
    ResultPageSize = 500   # AD paging — controls LDAP page size, not our batch size
}
if ($SearchBase) {
    $getParams.SearchBase = $SearchBase
}

# ── Helper: resolve manager DN to display name + UPN ──────────────────────────
$managerCache = @{}

function Resolve-Manager {
    param([string]$ManagerDN)
    if (-not $ManagerDN) { return @{ name = ""; upn = "" } }

    if ($managerCache.ContainsKey($ManagerDN)) {
        return $managerCache[$ManagerDN]
    }

    try {
        $mgr = Get-ADUser -Identity $ManagerDN -Properties DisplayName, UserPrincipalName
        $result = @{
            name = ($mgr.DisplayName ?? "")
            upn  = ($mgr.UserPrincipalName ?? "")
        }
    } catch {
        $result = @{ name = ""; upn = "" }
    }

    $managerCache[$ManagerDN] = $result
    return $result
}

# ── Helper: push a batch to the API ───────────────────────────────────────────
function Push-Batch {
    param([array]$Users)
    if ($Users.Count -eq 0) { return }

    $endpoint = "$ApiUrl/api/identity-providers/$ProviderId/push"
    $body = @{ users = $Users } | ConvertTo-Json -Depth 4 -Compress

    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method POST -Body $body `
            -ContentType "application/json" `
            -Headers @{ Authorization = "Bearer $Token" } `
            -TimeoutSec 30

        Write-Host "  Pushed $($Users.Count) users" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to push batch: $($_.Exception.Message)"
    }
}

# ── Helper: extract group names from MemberOf DNs ─────────────────────────────
function Get-GroupNames {
    param([object[]]$MemberOf)
    if (-not $MemberOf) { return @() }

    return $MemberOf | ForEach-Object {
        # Extract CN from DN: "CN=Domain Admins,CN=Users,DC=corp,DC=local" → "Domain Admins"
        if ($_ -match '^CN=([^,]+)') { $Matches[1] } else { $_ }
    }
}

# ── Main: stream AD users and push in batches ─────────────────────────────────
Write-Host "NanoSIEM AD Identity Sync" -ForegroundColor Cyan
Write-Host "  API:       $ApiUrl"
Write-Host "  Provider:  $ProviderId"
Write-Host "  Batch:     $BatchSize users per push"
Write-Host "  Filter:    $ldapFilter"
if ($SearchBase) { Write-Host "  Base:      $SearchBase" }
Write-Host ""

$batch = [System.Collections.Generic.List[object]]::new()
$totalPushed = 0
$startTime = Get-Date

# Stream users — Get-ADUser with ResultPageSize handles LDAP paging internally.
# We never hold more than $BatchSize users in memory.
Get-ADUser @getParams | ForEach-Object {
    $user = $_

    # Resolve manager (cached)
    $mgr = Resolve-Manager -ManagerDN $user.Manager

    # Map AD attributes → NanoSIEM identity schema
    $record = @{
        external_id    = $user.ObjectGUID.ToString()
        username       = $user.SamAccountName
        upn            = ($user.UserPrincipalName ?? "")
        email          = ($user.Mail ?? "")
        display_name   = ($user.DisplayName ?? "")
        first_name     = ($user.GivenName ?? "")
        last_name      = ($user.Surname ?? "")
        department     = ($user.Department ?? "")
        title          = ($user.Title ?? "")
        manager_upn    = $mgr.upn
        manager_display_name = $mgr.name
        company        = ($user.Company ?? "")
        office_location = ($user.Office ?? "")
        city           = ($user.City ?? "")
        country        = ($user.Country ?? "")
        groups         = @(Get-GroupNames -MemberOf $user.MemberOf)
        account_enabled = [bool]$user.Enabled
        phone          = ($user.telephoneNumber ?? "")
        employee_id    = ($user.EmployeeID ?? "")
        employee_type  = if ($user.EmployeeType) { $user.EmployeeType } else { "employee" }
        last_sign_in_at = if ($user.LastLogonDate) { $user.LastLogonDate.ToUniversalTime().ToString("o") } else { $null }
        created_in_directory_at = if ($user.WhenCreated) { $user.WhenCreated.ToUniversalTime().ToString("o") } else { $null }
    }

    $batch.Add($record)

    if ($batch.Count -ge $BatchSize) {
        Push-Batch -Users $batch.ToArray()
        $totalPushed += $batch.Count
        $batch.Clear()
    }
}

# Push remaining
if ($batch.Count -gt 0) {
    Push-Batch -Users $batch.ToArray()
    $totalPushed += $batch.Count
}

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "Done. Pushed $totalPushed users in $([math]::Round($elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
