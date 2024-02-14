param (
    [string[]]
    [ValidateSet("AppRegistrations", "Devices", "Groups", "ServicePrincipals", "Users")]
    $AADObjects = @("AppRegistrations", "Devices", "Groups", "ServicePrincipals", "Users"),

    [bool]
    $SaveToFile = $True,

    [guid]
    [Parameter(Mandatory)]
    $AppID,

    [string]
    [Parameter(Mandatory)]
    $CertificateThumbprint,

    [guid]
    [Parameter(Mandatory)]
    $TenantId
)
#Requires -Modules @{"ModuleName"="Microsoft.Graph.Authentication"; "RequiredVersion"= "2.12.0"}
#Requires -Modules @{"ModuleName"="Microsoft.Graph.Applications"; "RequiredVersion"= "2.12.0"}
#Requires -Modules @{"ModuleName"="Microsoft.Graph.Groups"; "RequiredVersion"= "2.12.0"}
#Requires -Modules @{"ModuleName"="Microsoft.Graph.Users"; "RequiredVersion"= "2.12.0"}
#Requires -Modules @{"ModuleName"="Microsoft.Graph.Identity.DirectoryManagement"; "RequiredVersion"= "2.12.0"}

$Script:AppID = $AppID
$Script:CertificateThumbprint = $CertificateThumbprint
$Script:TenantId = $TenantId

Connect-MgGraph -NoWelcome -TenantId $Script:TenantId -ClientId $Script:AppID -CertificateThumbprint $Script:CertificateThumbprint


$Script:ObjectParameters = @{
    "AppRegistrations" = @{ 
        "GraphProperties" = @(
                "Id", #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
                "DeletedDateTime",
                "Api",
                "AppId",
                "ApplicationTemplateId",
                "CreatedDateTime",
                "DisplayName",
                "Description",
                "IdentifierUris",
                "Info",
                "Notes",
                "PublisherDomain",
                "RequiredResourceAccess",
                "SignInAudience",
                "Tags",
                "Web"
        )
        "EnrichmentProperties" = @{
            "Owners" = @{"URI" = "/applications/<Id>/owners?`$select=id,userPrincipalName"}
        }
        "LAWProperties" = @{ "DCE" = "https://sentinel-law-dce-xynb.eastus-1.ingest.monitor.azure.com/"
                             "DCR" = "dcr-413fc5c3cdf640a49cb6a0b21dd769ba"
                             "Table" = "AADAppRegistrations"
        }
    }
    "Devices" = @{
        "GraphProperties" = @(
            "Id",  #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
            "DeletedDateTime",
            "AccountEnabled",
            "ApproximateLastSignInDateTime",
            "CreatedDateTime",
            "DeviceCategory",
            "DeviceId",
            "DeviceOwnership"
            "DisplayName",
            "DomainName",
            "IsCompliant",
            "IsManaged",
            "IsRooted",
            "ManagementType",
            "Manufacturer",
            "MDMAppId",
            "Model",
            "OnPremisesLastSyncDateTime",
            "OnPremisesSyncEnabled",
            "OperatingSystem",
            "OperatingSystemVersion",
            "ProfileType",
            "RegistrationDateTime",
            "TrustType",
            "ExtensionAttributes"
            )
        "EnrichmentProperties" = @{
            "RegisteredOwners" = @{"URI" = "/devices/<Id>/registeredOwners?`$select=id,userPrincipalName"}
            "RegisteredUsers"  = @{"URI" = "/devices/<Id>/registeredUsers?`$select=id,userPrincipalName"}
            "MemberOf" = @{"URI" = "/devices/<Id>/memberOf?`$select=id,displayName,mail"}
        }
        "LAWProperties" = @{ "DCE" = "https://sentinel-law-dce-xynb.eastus-1.ingest.monitor.azure.com/"
                             "DCR" = ""
                             "Table" = "AADDevices"
        }
    }
    "Groups" = @{
        "GraphProperties" = @(
            "Id",  #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
            "DeletedDateTime",
            "Classification",
            "CreatedDateTime",
            "Description",
            "DisplayName",
            "ExpirationDateTime",
            "GroupTypes",
            "IsAssignableToRole",
            "Mail",
            "MailEnabled",
            "MailNickname",
            "MembershipRule",
            "OnPremisesDomainName",
            "OnPremisesLastSyncDateTime",
            "OnPremisesNetBiosName",
            "OnPremisesSamAccountName",
            "OnPremisesSecurityIdentifier",
            "OnPremisesSyncEnabled",
            "ProxyAddresses",
            "RenewedDateTime",
            "SecurityEnabled",
            "SecurityIdentifier",
            "Visibility"
            )
        "EnrichmentProperties" = @{
            "Owners" = @{"URI" = "/groups/<Id>/owners?`$select=id,userPrincipalName"}
        }
        "LAWProperties" = @{ "DCE" = "https://sentinel-law-dce-xynb.eastus-1.ingest.monitor.azure.com/"
                             "DCR" = ""
                             "Table" = "AADGroups"
        }
    }
    "ServicePrincipals" = @{
        "GraphProperties" = @(
            "Id", #Renamed ObjectId in DCR
            "AccountEnabled",
            "AlternativeNames",
            "AppDisplayName",
            "AppId",
            "AppOwnerOrganizatoinId",
            "AppRoles",
            "CreatedDateTime",
            "DisplayName",
            "Info",
            "ServicePrincipalType",
            "SignInAudience",
            #"Oauth2PermissionScopes",
            "VerifiedPublisher"
        )
        "EnrichmentProperties" = @{
            "Owners" = @{"URI" = "/servicePrincipals/<Id>/owners?`$select=id,userPrincipalName"}
            "AppRoleAssignments" = @{"URI" = "/servicePrincipals/<Id>/appRoleAssignments?`$select=appRoleId,createdDateTime,resourceDisplayName,resourceId"}
            "MemberOf" = @{"URI" = "/servicePrincipals/<Id>/memberOf?`$select=id,displayName,mail"}
        }
        "LAWProperties" = @{ "DCE" = "https://sentinel-law-dce-xynb.eastus-1.ingest.monitor.azure.com/"
                             "DCR" = ""
                             "Table" = "AADServicePrincipals"

        }
    }
    "Users" = @{
        "GraphProperties" = @(
            "Id",  #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
            "CreatedDateTime",
            "CreationType",
            "CustomSecurityAttributes",
            "DisplayName",
            "GivenName",
            "JobTitle",
            "LastPasswordChangeDateTime",
            "Mail",
            "MobilePhone",
            "OfficeLocation",
            "OnPremisesDistinguishedName",
            "OnPremisesDomainName",
            "OnPremisesImmutableId",
            "OnPremisesLastSyncDateTime",
            "OnPremisesSamAccountName",
            "OnPremisesSecurityIdentifier",
            "OnPremisesSyncEnabled",
            "OnPremisesUserPrincipalName",
            "ProxyAddresses",
            "SecurityIdentifier"
            "Surname",
            "UserPrincipalName",
            "UserType"
            )
        "EnrichmentProperties" = @{
            "AuthenticationMethods" = @{"URI" = "/users/<Id>/authentication/methods"} #This is an easily throttled property (in my testing).
            "MemberOf" = @{"URI" = "/users/<Id>/memberOf?`$select=id,displayName,mail"}
            "OwnedDevices" = @{"URI" = "/users/<Id>/ownedDevices?`$select=id,displayName,deviceId,profileType"}
        }
        "LAWProperties" = @{ "DCE" = "https://sentinel-law-dce-xynb.eastus-1.ingest.monitor.azure.com/"
                             "DCR" = "dcr-1bff4b7114384b3cae1adcd4fcf08ae2"
                             "Table" = "AADUsers"
        }
    }
}


function Build-BatchGraphQuery {
    param (
        [psobject[]]
        $Objects
    )
    
    $BatchSize = 20
    $HTTPRequests = for ($i = 0; $i -lt $Objects.Length; $i += $BatchSize) {
        $end = $i + $BatchSize - 1
        if ($end -ge $Objects.Length) { $end = $Objects.Length }
        $index = $i
        $Requests = $Objects[$i..($end)] | ForEach-Object {
            $Id = $_.Id
            [PSCustomObject]@{
                'Id'     = $Id
                'Method' = 'GET'
                'Url'    = $Script:ObjectParameters[$EnrichmentAADObjType]["EnrichmentProperties"][$QueryType]["URI"] -replace "<Id>", $Id
            }
            ++$index
        }

        @{
            'Headers'     = @{"Content-Type" = "application/json"}
            'Method'      = 'POST'
            'Uri'         = 'https://graph.microsoft.com/v1.0/$batch'
            'Body'        = @{
                'requests' = @($Requests)
            
            } | ConvertTo-Json -Depth 100
        }
    }

    return $HTTPRequests
}

function Send-BatchGraphQuery {
    param (
        [psobject[]]
        $Objects,

        [string]
        $EnrichmentAADObjType,

        [string]
        $TimeGenerated
    )

    $Results = $Objects | Group-Object -AsHashTable -Property id

        #Build 20 Graph Requests into 1 HTTP Request. Thanks! https://nicolasuter.medium.com/optimising-microsoft-graph-powershell-scripts-3eb76a280077
        ForEach ($QueryType in $Script:ObjectParameters[$EnrichmentAADObjType]["EnrichmentProperties"].Keys) {

            ######TEST#########
            $ParallelStopWatch =  [system.diagnostics.stopwatch]::StartNew()
            #####################

            $CompleteHTTPResults = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
            $RemainingIdentities = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
            ($Objects | Group-Object -AsHashTable -Property id).GetEnumerator() | ForEach-Object { $RemainingIdentities.TryAdd($_.Key, $_.Value) | Out-Null }

            #Continue trying until all requests are successful
            while ($RemainingIdentities.Count -ne 0) {

                $HTTPRequests = Build-BatchGraphQuery -Objects $RemainingIdentities.Values
                $HTTPRequests | ForEach-Object -Parallel {
                    $TempResponses = $using:CompleteHTTPResults
                    $TRemainingIdentities = $using:RemainingIdentities
                    
                    try {   $HTTPResponse = Invoke-MgGraphRequest @PSItem }
                    catch { continue } #!!!!!!Potential infinite loop here if you fuck up the request values and it is always wrong.
                                       #Or if MS b&s you... I have not seen cases where the overall Graph request returns 429, only the sub-queries. 

                    #If ANY response in the batch return 429//Timeout, then wait. 15 to be kind.
                    if ($HTTPResponse.responses.status -contains "429") {
                        Start-Sleep -Seconds 15
                    }

                    $HTTPResponse.responses | ForEach-Object { 
                        if ($PSItem.status -eq 200) {
                            $TempResponses.TryAdd($PSItem.id,$PSItem.body.value) | Out-Null

                            #This request was successful so remove it from the list. 
                            $Popr = $null
                            $TRemainingIdentities.TryRemove($PSItem.id, [ref]$Popr) | Out-Null

                        } elseif ($PSItem.status -eq 429) {
                            #Request was throttled. Leave it in the queue.
                            continue 
                        }

                        else {
                            #A different error happened. Overwrite whatever the return is.
                            $TempResponses.TryAdd($PSItem.id,"GraphError") | Out-Null

                            #And give up.
                            $Popr = $null
                            $TRemainingIdentities.TryRemove($PSItem.id, [ref]$Popr) | Out-Null
                        }
                    }
                }
            }

            ######TIMER STUFF###############
            $ParallelStopWatch.stop()
            Write-Host "Got....$QueryType in: $ParallelStopWatch"
            ######TIMER STUFF###############

            $CompleteHTTPResults.GetEnumerator() | ForEach-Object {
                $TempObject = $Results[$_.Key] 
                
                #Force is needed here because the Graph Object might already have the property name we are writing (but it is empty)
                $TempObject | Add-Member -Type NoteProperty -Name $QueryType -Value $_.Value -Force
                ##Lol easier to force it then looping or adding logic to check if we already added it.
                $TempObject | Add-Member -Type NoteProperty -Name "TimeGenerated" -Value $TimeGenerated -Force

                $Results[$_.Key] = $TempObject
            }
        }

    return $Results.Values
}

function Export-AADObjects {
    param(
        [string]
        $AADObjType
    )

    $InitialQueryWatch = [system.diagnostics.stopwatch]::StartNew()

    #Graph PowerShell handles the pagination for us. Yay
    $GraphParams = @{   "All" = $true
                        "PageSize" = 999
                        "Property" = $Script:ObjectParameters[$AADObjType]["GraphProperties"]
                    }
    $Responses = switch ($AADObjType) {
        "AppRegistrations"      {   Get-MgApplication @GraphParams}
        "Devices"               {   Get-MgDevice @GraphParams }
        "Groups"                {   Get-MgGroup @GraphParams}
        "ServicePrincipals"     {   Get-MgServicePrincipal @GraphParams }
        "Users"                 {   Get-MgUser @GraphParams }

        Default {}
    }

    $InitialQueryWatch.Stop()
    Write-Host "Got All $AADObjType in: $InitialQueryWatch" -ForegroundColor "Green"

    $EnrichedResponses = Send-BatchGraphQuery -Objects $Responses -EnrichmentAADObjType $AADObjType -TimeGenerated (Get-Date -AsUTC -Format "s")

    $CombinedProperties = $Script:ObjectParameters[$AADObjType]["GraphProperties"] + 
                          $Script:ObjectParameters[$AADObjType]["EnrichmentProperties"].Keys +
                          "TimeGenerated" | Sort-Object

    $FieldSelectedResponses = $EnrichedResponses | ForEach-Object {
        $_ | Select-Object -Property $CombinedProperties
    }

    return $FieldSelectedResponses
}

ForEach ($ObjectType in $AADObjects) {
    $Entries = Export-AADObjects -AADObjType $ObjectType

    if ($SaveToFile) {
        $Entries | ConvertTo-Json -Depth 20 | Out-File -FilePath "$PSScriptRoot\$ObjectType.json"
    }
}
