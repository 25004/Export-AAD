# Export-AAD
A script to export all of your identity objects from Azure Active Directory into JSON text files. (So you can send them to a SIEM.)

Support for:
- Enterprise size tenants (>5,000 entities)
- Identity Objects:
    - Application Registrations
    - Devices
    - Groups
    - Service Principals (aka Enterprise Applications)
    - Users
- The ability to change what properties are exported for each object.
- Batching and parallelism to make Graph queries go faster
- Option for Sentinel ingestion.

To get more specifics on what is exported and how to change it see Default Identity Object Properties.

> [!WARNING]
> There is incomplete error handling. You should test in your environment first.

## Overview
Inventory information is invaluable for cybersecurity. Understanding the current state of your environment (and how it looked at a specific time) allows you to enrich detections and incident response investigations. For more on the potential Use Cases of this data, see the [blog post](#################).

Even though this data is valuable for cybersecurity, Microsoft does not provide a great way to access it at scale. Microsoft offers ["Graph Data Connect"](https://learn.microsoft.com/en-us/graph/data-connect-datasets), but this is focused on M365 and does not return all the objects (no apps/SPs) or all fields of interest (auth methods, role memberhships, group memberships). For more, see the blog above.

That is why I created this script. It iterates through the provided identity objects and exports certain attributes from AAD. You can then send this to your SIEM. 

This script is meant to be run on a schedule (twice a day, daily, etc) in a SOAR platform or data pipeline.

## Requirements

### PowerShell Modules:
- Microsoft.Graph.Authentication
- Microsoft.Graph.Applications
- Microsoft.Graph.Groups
- Microsoft.Graph.Users
- Microsoft.Graph.Identity.DirectoryManagement

### Application Permissions:

- Directory.Read.All
- UserAuthenticationMethod.Read.All (for viewing user auth)

For directions on how to grant an application Graph API permissions read [Get access without a user](https://learn.microsoft.com/en-us/graph/auth-v2-service?tabs=http). Only certificate-based application authentication is supported. But you can edit the script to support passwords if you want.

## Example Commands
Export all object types and save to a folder.
```PowerShell
.\Export-AAD.ps1 -AppID "appidhere" -CertificateThumbprint "certthumbprinthere" -TenantId "tenantidhere" -SaveToFile
```

Export only the provided object types
```PowerShell
.\Export-AAD.ps1 -AppID "appidhere" -CertificateThumbprint "certthumbprinthere" -TenantId "tenantidhere" -SaveToFile -AADObjects "Users", "Devices"
```

> [!TIP]
> The User AuthenticationMethods property is often throttled. It might be limited to ~100 users/minute. Remove it if you want to go faster. 

## Edit Returned Identity Properties
The returned properties and enrichments are in ```$Script:ObjectParameters``` near the top of the script.

This is a nested hashtable that should be straightforward to change. You should test how the property is returned by Graph API.

A small difference is that ```EnrichmentProperties``` is the URI of the request and this is populated and passed to ```Invoke-MgGraphRequest```. To edit those properties you must edit the URI.

## Optimizations
Microsoft is pushing everyone to the Graph API. However, the Graph PowerShell module is too slow for this use case. It does not support batching or parallelism.

To ensure fast execution in large tenants, I looked for optimizations. This includes:

1. Graph Request Batching
2. Parallelism

In my test tenant with 5,000 users and 2,000 groups:

- Graph PowerShell module:   1 hour 40 minutes
- Export-AAD:  11 minutes

### Graph Request Batching
I implemented custom batching for individual **enrichment** requests. Graph API supports sending up to 20 Graph requests inside 1 HTTP request. This is called [batching](https://learn.microsoft.com/en-us/graph/json-batching) and greatly reduces the number of network requests.
However, Microsoft's Graph PowerShell modules [do not support batching](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/116).

Thanks to [this blog by Nicola Suter](https://nicolasuter.medium.com/optimising-microsoft-graph-powershell-scripts-3eb76a280077) for many good tips.

 Enrichments are used when a Property is not available in the return set for that object type. For example: authentication methods is not returned on the user object and requires a separate request. 

**However**, the first dump of an object (e.g. get all users) is done using Graph PowerShell. This is because:
1. It supports a max ```PageSize``` of 999 and is therefore more network performant.
2. It supports the ```All``` parameter, so it is easy to implement.
3. It is generally quite fast?


### Parallelism
The 20 Graph API requests are batched together into 1 HTTP request. The list of all HTTP requests for an object type are sent in parallel using ```ForEach-Object -Parallel```. The results are interpreted individually and any that are throttled are resent.

## Future Improvements

- More error handling
- Can you parallelize the initial requests...? Or the entire object flows? 🤔
- Test more back off logic. Does exponential backoff actually help? In my quick testing, waiting 10 seconds or 1 minute made no difference.

## Default Identity Object Properties
I selected security relevant fields for each object type. If you want to add or remove fields, see the next section. Most fields are dynamic, so refer to the [Graph API reference](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0) or the sample results folder for examples.

    Application Registrations
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
    "Owners",
    "PublisherDomain",
    "RequiredResourceAccess",
    "SignInAudience",
    "Tags",
    "Web"       
--

    Devices
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
    "MemberOf",
    "Model",
    "OnPremisesLastSyncDateTime",
    "OnPremisesSyncEnabled",
    "OperatingSystem",
    "OperatingSystemVersion",
    "ProfileType",
    "RegisteredOwners",
    "RegisteredUsers",
    "RegistrationDateTime",
    "TrustType",
    "ExtensionAttributes"
--    

    Groups
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
    "Owners",
    "ProxyAddresses",
    "RenewedDateTime",
    "SecurityEnabled",
    "SecurityIdentifier",
    "Visibility"
--
    
    Service Principals (aka Enterprise Applications)
    "Id", #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
    "AccountEnabled",
    "AlternativeNames",
    "AppDisplayName",
    "AppId",
    "AppOwnerOrganizatoinId",
    "AppRoles",
    "AppRoleAssignments",
    "CreatedDateTime",
    "DisplayName",
    "Info",
    "Owners",
    "MemberOf",
    "ServicePrincipalType",
    "SignInAudience",
    "VerifiedPublisher"
--

    Users
    "Id",  #MUST BE RENAMED IN YOUR DCR. (ObjectId is good option)
    "AuthenticationMethods",
    "CreatedDateTime",
    "CreationType",
    "CustomSecurityAttributes",
    "DisplayName",
    "GivenName",
    "JobTitle",
    "LastPasswordChangeDateTime",
    "Mail",
    "MemberOf",
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
    "OwnedDevices",
    "ProxyAddresses",
    "SecurityIdentifier"
    "Surname",
    "UserPrincipalName",
    "UserType"



