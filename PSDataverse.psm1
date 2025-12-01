function Connect-PSDVOrg {
    <#
    .SYNOPSIS
    Establishes a connection to a Microsoft Dataverse organization.

    .DESCRIPTION
    Connect-PSDVOrg creates an authenticated connection to a Microsoft Dataverse environment using various authentication methods.
    It supports service principal authentication with client secrets, managed identity authentication, and interactive login.
    Upon successful connection, it retrieves and stores an access token for subsequent Dataverse API calls.

    .PARAMETER ClientID
    The Application (client) ID of the Azure AD application registration used for service principal authentication.

    .PARAMETER ClientSecret
    The client secret (secure string) for the Azure AD application used for service principal authentication.

    .PARAMETER ManagedIdentityID
    The object ID of the managed identity to use for authentication in Azure environments.

    .PARAMETER AzureTenantId
    The Azure Active Directory tenant ID where the Dataverse environment is located.

    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Dataverse environment (required for interactive login).

    .PARAMETER DataverseOrgURL
    The URL of the Dataverse organization (e.g., https://orgname.crm.dynamics.com/).

    .PARAMETER Environment
    The Azure cloud environment. Valid values are AzureCloud, AzureChinaCloud, AzureUSGovernment, or AzureGermanCloud.

    .EXAMPLE
    Connect-PSDVOrg -AzureTenantId "12345678-1234-1234-1234-123456789012" -SubscriptionId "87654321-4321-4321-4321-210987654321" -DataverseOrgURL "https://contoso.crm.dynamics.com/" -Environment "AzureCloud"

    Connects to Dataverse using interactive authentication.

    .EXAMPLE
    $secret = ConvertTo-SecureString "MyClientSecret" -AsPlainText -Force
    Connect-PSDVOrg -ClientID "12345678-1234-1234-1234-123456789012" -ClientSecret $secret -AzureTenantId "87654321-4321-4321-4321-210987654321" -DataverseOrgURL "https://contoso.crm.dynamics.com/" -Environment "AzureCloud"

    Connects to Dataverse using service principal authentication.

    .EXAMPLE
    Connect-PSDVOrg -ManagedIdentityID "12345678-1234-1234-1234-123456789012" -DataverseOrgURL "https://contoso.crm.dynamics.com/" -Environment "AzureCloud"

    Connects to Dataverse using managed identity authentication.
    #>

    [CmdletBinding(DefaultParameterSetName = 'InteractiveLogin')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [String]
        $ClientID,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [SecureString]
        $ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')]
        [String]
        $ManagedIdentityID,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory, ParameterSetName = 'InteractiveLogin')]
        [String]
        $AzureTenantId,

        [Parameter(Mandatory, ParameterSetName = 'InteractiveLogin')]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory)]
        [String]
        $DataverseOrgURL,

        [Parameter(Mandatory)]
        [ValidateSet('AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureGermanCloud')]
        [String]
        $Environment
    )

    $ConnectAzAccountParams = @{}
    

    switch ($PSCmdlet.ParameterSetName) {
        'ClientSecret' {
            $clientCredential = [System.Management.Automation.PSCredential]::new($ClientID, $ClientSecret)
            $ConnectAzAccountParams.Add('Credential', $clientCredential)
            $ConnectAzAccountParams.Add('TenantID', $AzureTenantId)
            $ConnectAzAccountParams.Add('ServicePrincipal', $true)
        }

        'ManagedIdentity' {
            $ConnectAzAccountParams.Add('Identity', $true)
            $ConnectAzAccountParams.Add('AccountID', $ManagedIdentityID)
        }

        'InteractiveLogin' {
            $ConnectAzAccountParams.Add('Environment', $Environment)
            $ConnectAzAccountParams.Add('Tenant', $AzureTenantId)
            $ConnectAzAccountParams.Add('Subscription', $SubscriptionId)
        }
    }

    #Ensure DataverseOrgURL has a trailing slash
    if (-not $DataverseOrgURL.EndsWith('/')) {
        $DataverseOrgURL = $DataverseOrgURL + '/'
    }
    
    try {
        Write-Verbose "Connecting to Azure Tenant $AzureTenantId"
        Connect-AzAccount @ConnectAzAccountParams
    }
    catch {
        throw "Error executing $($_.InvocationInfo.MyCommand.Name), $($_.ToString())"
    }

    try {
        Write-Verbose "Getting Dataverse Access Token for $DataverseOrgUrl"
        $Global:DATAVERSEACCESSTOKEN = Get-AzAccessToken -ResourceUrl $DataverseOrgURL -AsSecureString
        $Global:DATAVERSEORGURL = $DataverseOrgURL
    }
    catch {
        throw "Error executing $($_.InvocationInfo.MyCommand.Name), $($_.ToString())"
    }

}


function Update-PSDVAccessToken {
    <#
    .SYNOPSIS
    Updates the Dataverse access token if it's close to expiration.

    .DESCRIPTION
    Update-PSDVAccessToken checks if the current Dataverse access token will expire within 5 minutes.
    If the token is approaching expiration, it automatically refreshes the token to ensure continued
    access to the Dataverse API without interruption.

    .EXAMPLE
    Update-PSDVAccessToken

    Checks and refreshes the access token if needed.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    if (($Global:DATAVERSEACCESSTOKEN.ExpiresOn).AddMinutes(-5) -le (Get-Date).ToUniversalTime() ) {
        if ($PSCmdlet.ShouldProcess("Access Token", "Refresh")) {
            $Global:DATAVERSEACCESSTOKEN = Get-AzAccessToken -ResourceUrl $Global:DATAVERSEORGURL -AsSecureString
        }
    }
}

function Invoke-PSDVWebRequest {
    <#
    .SYNOPSIS
    Executes authenticated web requests to the Dataverse Web API.

    .DESCRIPTION
    Invoke-PSDVWebRequest is the core function for making authenticated HTTP requests to the Microsoft Dataverse Web API.
    It handles OAuth authentication, URL construction, query parameter formatting, and automatic pagination.
    The function supports all HTTP methods (GET, POST, PATCH, DELETE, PUT) and automatically follows OData nextLink
    properties to retrieve complete result sets for large datasets.

    .PARAMETER WebUri
    The Web API endpoint URI. Can be a full URL, relative path with 'api/data/v9.2/', or just the resource name.

    .PARAMETER Method
    The HTTP method to use. Valid values are Get, Post, Patch, Delete, or Put. Default is Get.

    .PARAMETER Select
    OData $select parameter to specify which fields to return.

    .PARAMETER Filter
    OData $filter parameter to specify query conditions.

    .PARAMETER Expand
    OData $expand parameter to include related records.

    .PARAMETER Body
    Hashtable containing the request body data for POST/PATCH operations.

    .PARAMETER Headers
    Additional HTTP headers to include in the request.

    .PARAMETER ReturnRawResponse
    Returns the raw web response object instead of parsing the JSON content.

    .EXAMPLE
    Invoke-PSDVWebRequest -WebUri "accounts" -Select "name,accountnumber"

    Retrieves all accounts with only name and account number fields.

    .EXAMPLE
    Invoke-PSDVWebRequest -WebUri "contacts" -Filter "firstname eq 'John'" -Expand "parentcustomerid_account"

    Retrieves contacts named John and expands the parent account information.

    .EXAMPLE
    $data = @{ name = "New Account"; accountnumber = "ACC001" }
    Invoke-PSDVWebRequest -WebUri "accounts" -Method Post -Body $data

    Creates a new account record.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [String]
        $WebUri,

        [parameter()]
        [ValidateSet('Get', 'Post', 'Patch', 'Delete', 'Put')]
        [string]
        $Method = 'Get',

        [parameter()]
        [string]
        $Select,

        [parameter()]
        [string]
        $Filter,

        [parameter()]
        [string]
        $Expand,

        [parameter()]
        [hashtable]
        $Body,

        [parameter()]
        [hashtable]
        $Headers,

        [parameter()]
        [switch]
        $ReturnRawResponse = $false
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    Update-PSDVAccessToken

    # Remove leading slash if present
    if ($WebUri.StartsWith('/')) {
        $WebUri = $WebUri.Substring(1)
    }

    if ($WebUri.StartsWith(($Global:DATAVERSEORGURL))) {
        $dvRequestUri = $WebUri
    }
    elseif ( $WebUri.Contains('api/data/v9.2/') ) {
        $dvRequestUri = $Global:DATAVERSEORGURL + $WebUri
    }
    else {
        $dvRequestUri = $Global:DATAVERSEORGURL + 'api/data/v9.2/' + $WebUri
    }
    $dvRequestUri = [System.UriBuilder]$dvRequestUri

    # Append query parameters if provided
    $queryParams = @{}
    if ($Select) { $queryParams['$select'] = $Select }
    if ($Filter) { $queryParams['$filter'] = $Filter }
    if ($Expand) { $queryParams['$expand'] = $Expand }

    if ($queryParams.Count -gt 0) {
        $existingQuery = $dvRequestUri.Query
        if ($existingQuery.StartsWith('?')) {
            $existingQuery = $existingQuery.Substring(1)
        }
        $newQuery = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
        if ($existingQuery) {
            $dvRequestUri.Query = "$existingQuery&$newQuery"
        }
        else {
            $dvRequestUri.Query = $newQuery
        }
    }

    if ($Body) {
        if ($Method -eq 'Get') {
            $Method = 'Post'
        }

        $bodyContent = $Body | ConvertTo-Json
        $httpHeaders = @{
            'Content-Type' = 'application/json'
            'Accept'       = 'application/json'
        }
    }
    else {
        $bodyContent = $null
        $httpHeaders = @{}
    }

    if ($PSBoundParameters.ContainsKey('Headers')) {
        foreach ($key in $Headers.Keys) {
            $httpHeaders[$key] = $Headers[$key]
        }
    }

    try {
        Write-Verbose "Executing Web API: $($dvRequestUri.Uri.AbsoluteUri)"
        $webResponse = Invoke-WebRequest -Authentication OAuth -Token $Global:DATAVERSEACCESSTOKEN.Token -Method $method -Uri $dvRequestUri.Uri.AbsoluteUri -Body $bodyContent -Headers $httpHeaders
    }
    catch {
        if ($_.ErrorDetails) {
            try {
                $errorContent = (ConvertFrom-Json $_.ErrorDetails.ToString()).error
            }
            catch {
                $errorContent = $_.ErrorDetails.ToString()
            }
        }
        else {
            $errorContent = $_.ToString()
        }
        throw "Error executing web query: $($_.Exception.Message), $errorContent"
    }

    if ($ReturnRawResponse) {
        return $webResponse
    }
    else {
        $jsonResponse = $webResponse.Content | ConvertFrom-Json
        $allResults = @()

        # Handle paging by following @odata.nextLink
        do {
            if ($jsonResponse.value) {
                $allResults += $jsonResponse.value
            }
            else {
                # Single item response (no .value property)
                return $jsonResponse
            }

            # Check if there's a next page
            if ($jsonResponse.'@odata.nextLink') {
                try {
                    Write-Verbose "Following pagination link: $($jsonResponse.'@odata.nextLink')"
                    $webResponse = Invoke-WebRequest -Authentication OAuth -Token $Global:DATAVERSEACCESSTOKEN.Token -Method Get -Uri $jsonResponse.'@odata.nextLink' -Headers $httpHeaders
                    $jsonResponse = $webResponse.Content | ConvertFrom-Json
                }
                catch {
                    Write-Warning "Error retrieving next page: $($_.Exception.Message)"
                    break
                }
            }
            else {
                $jsonResponse = $null
            }
        } while ($jsonResponse)

        return $allResults
    }
}

function Read-PSDVTableData {
    <#
    .SYNOPSIS
    Retrieves metadata for all tables in the Dataverse environment.

    .DESCRIPTION
    Read-PSDVTableData fetches information about all tables (entities) available in the connected Dataverse environment.
    It returns basic metadata including logical names, display names, and entity set names for each table.
    This function is marked as legacy and is primarily used for compatibility with older code.

    .EXAMPLE
    Read-PSDVTableData

    Returns metadata for all tables in the Dataverse environment.

    .EXAMPLE
    Read-PSDVTableData | Where-Object { $_.LogicalName -like "*custom*" }

    Returns metadata for all custom tables (containing "custom" in the name).
    #>

#legacy function

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    try {
        $webResponse = Invoke-PSDVWebRequest -Method Get -WebUri ($Global:DATAVERSEORGURL + 'api/data/v9.2/EntityDefinitions?$select=DisplayName,LogicalName,EntitySetName')
    }
    catch {
        throw "Error getting Dataverse Entity Definitions: $($_.InvocationInfo.MyCommand.Name), $($_.ToString())"
    }


    foreach ($t in $webResponse) {
        [PSCustomObject]@{
            LogicalName = $t.LogicalName
            DisplayName   = $t.DisplayName.LocalizedLabels[0].Label
            EntitySetName = $t.EntitySetName
        }
    }
}


function Get-PSDVTableDetail {
    <#
    .SYNOPSIS
    Retrieves detailed metadata for a specific Dataverse table.

    .DESCRIPTION
    Get-PSDVTableDetails fetches comprehensive metadata for a specified Dataverse table, including
    the table definition and all field/column information. It returns a detailed object containing
    table properties and a Fields collection with information about each attribute in the table.
    This function provides schema information useful for understanding table structure.

    .PARAMETER Table
    The logical name of the Dataverse table to retrieve details for.

    .EXAMPLE
    Get-PSDVTableDetails -Table "account"

    Returns detailed metadata for the Account table including all field definitions.

    .EXAMPLE
    $tableInfo = Get-PSDVTableDetails -Table "contact"
    $tableInfo.Fields.Keys

    Gets table details and lists all available field names.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [String]
        $Table
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }


    #Get table details
    try {
        $webResponse = Invoke-PSDVWebRequest  -Method Get -WebUri ($Global:DATAVERSEORGURL + "api/data/v9.2/EntityDefinitions(LogicalName='$Table')")
    }
    catch {
        throw "Error getting table details: $($_.InvocationInfo.MyCommand.Name), $($_.ToString())"
    }

    $tableDetails = $webResponse

    #get fields / column details
    try {
        $webResponse = Invoke-PSDVWebRequest  -Method Get -WebUri ($Global:DATAVERSEORGURL + "api/data/v9.2/EntityDefinitions(LogicalName='$Table')/Attributes")
    }
    catch {
        throw "Error getting attribute details: $($_.InvocationInfo.MyCommand.Name), $($_.ToString())"
    }

    $columnDetails = $webResponse
    $columnDetailsProperties = @{}

    foreach ($column in $columnDetails) {
        $columnDetailsProperties.Add($column.LogicalName, $column)
    }

    # Create a hashtable with all properties including Fields
    $allProperties = @{ Fields = $columnDetailsProperties }

    # Add all original properties from tableDetails
    foreach ($property in $tableDetails.PSObject.Properties) {
        $allProperties[$property.Name] = $property.Value
    }

    # Create new PSCustomObject with all properties
    $tableDetailsWithFields = [PSCustomObject]$allProperties

    return $tableDetailsWithFields
}

function Get-PSDVTableColumn {
    <#
    .SYNOPSIS
    Retrieves column metadata for a specific Dataverse table.

    .DESCRIPTION
    Get-PSDVTableColumn returns detailed information about columns (attributes) in a specified Dataverse table.
    For each column, it provides metadata including logical name, display name, data type, validation rules,
    maximum length, precision, and relationship targets. This function is useful for understanding the
    structure and constraints of table fields before performing data operations. Optionally, you can specify
    specific column names to retrieve only those columns' metadata.

    .PARAMETER Table
    The logical name of the Dataverse table to retrieve column information for.

    .PARAMETER ColumnName
    Optional array of column logical names to retrieve. If not specified, all columns are returned.

    .EXAMPLE
    Get-PSDVTableColumn -Table "account"

    Returns detailed column information for all columns in the Account table.

    .EXAMPLE
    Get-PSDVTableColumn -Table "account" -ColumnName @("name", "telephone1", "websiteurl")

    Returns detailed column information for only the specified columns in the Account table.

    .EXAMPLE
    Get-PSDVTableColumn -Table "contact" | Where-Object { $_.RequiredLevel -eq "ApplicationRequired" }

    Returns only the required columns for the Contact table.

    .EXAMPLE
    Get-PSDVTableColumn -Table "account" -ColumnName @("accountid", "name") | Format-Table LogicalName, DisplayName, AttributeType

    Displays a formatted table of key column properties for specific columns.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [String]
        $Table,

        [parameter()]
        [String[]]
        $ColumnName
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    # Build the base URI for the attributes endpoint
    $baseUri = $Global:DATAVERSEORGURL + "api/data/v9.2/EntityDefinitions(LogicalName='$Table')/Attributes"
    
    # If specific column names are provided, build a filter expression
    if ($ColumnName -and $ColumnName.Count -gt 0) {
        $filterConditions = @()
        foreach ($column in $ColumnName) {
            $filterConditions += "LogicalName eq '$column'"
        }
        $filterExpression = $filterConditions -join ' or '
        $webResponse = Invoke-PSDVWebRequest -Method Get -WebUri $baseUri -Filter $filterExpression
    }
    else {
        $webResponse = Invoke-PSDVWebRequest -Method Get -WebUri $baseUri
    }

    foreach ($tableColumn in $webResponse) {
        [PSCustomObject]@{
            LogicalName = $tableColumn.LogicalName
            DisplayName = $tableColumn.DisplayName.LocalizedLabels[0].Label
            AttributeType = $tableColumn.AttributeType
            IsValidForCreate = $tableColumn.IsValidForCreate
            IsValidForUpdate = $tableColumn.IsValidForUpdate
            IsValidForRead = $tableColumn.IsValidForRead
            RequiredLevel = $tableColumn.RequiredLevel.Value
            MaxLength = $tableColumn.MaxLength
            Precision = $tableColumn.Precision
            Targets = $tableColumn.Targets -join ', '
        }
    }
}

function Get-PSDVTableItem {
    <#
    .SYNOPSIS
    Retrieves records from a Dataverse table.

    .DESCRIPTION
    Get-PSDVTableItem fetches one or more records from a specified Dataverse table. It supports both
    single record retrieval by ID and querying multiple records with filters. The function provides
    flexible parameter sets for different scenarios and includes support for field selection, record
    expansion, and filtering. Legacy parameter names are supported for backward compatibility but
    will generate deprecation warnings.

    .PARAMETER Table
    The logical name of the Dataverse table to retrieve records from.

    .PARAMETER EntitySet
    The entity set name of the Dataverse table (alternative to Table parameter).

    .PARAMETER ItemID
    The unique identifier (GUID) of a specific record to retrieve.

    .PARAMETER Filter
    OData filter expression to specify which records to retrieve.

    .PARAMETER Expand
    OData expand expression to include related records in the response.

    .PARAMETER Select
    Array of field names to include in the response (limits returned data).

    .PARAMETER FilterQuery
    Legacy parameter name for Filter (deprecated, use Filter instead).

    .PARAMETER ExpandQuery
    Legacy parameter name for Expand (deprecated, use Expand instead).

    .PARAMETER SelectFields
    Legacy parameter name for Select (deprecated, use Select instead).

    .EXAMPLE
    Get-PSDVTableItem -Table "account" -ItemID "12345678-1234-1234-1234-123456789012"

    Retrieves a specific account record by its ID.

    .EXAMPLE
    Get-PSDVTableItem -Table "contact" -Filter "firstname eq 'John'" -Select @("firstname", "lastname", "emailaddress1")

    Retrieves contacts named John with only specific fields.

    .EXAMPLE
    Get-PSDVTableItem -Table "account" -Filter "revenue gt 1000000" -Expand "primarycontactid"

    Retrieves accounts with revenue over $1M and includes primary contact details.

    .EXAMPLE
    Get-PSDVTableItem -EntitySet "accounts" -Filter "name contains 'Microsoft'"

    Retrieves accounts containing "Microsoft" in the name using entity set name.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameItemLookup')]
        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameQuery')]
        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameItemLookupLegacy')]
        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameQueryLegacy')]
        [String]
        $Table,

        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameItemLookup')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameQuery')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameItemLookupLegacy')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameQueryLegacy')]
        [string]
        $EntitySet,

        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameItemLookup')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameItemLookup')]
        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameItemLookupLegacy')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameItemLookupLegacy')]
        [guid]
        $ItemID,

        [parameter(ParameterSetName = 'TableLogicalNameQuery')]
        [parameter(ParameterSetName = 'TableEntitySetNameQuery')]
        [String]
        $Filter,

        [parameter(ParameterSetName = 'TableLogicalNameItemLookup')]
        [parameter(ParameterSetName = 'TableLogicalNameQuery')]
        [parameter(ParameterSetName = 'TableEntitySetNameItemLookup')]
        [parameter(ParameterSetName = 'TableEntitySetNameQuery')]
        [string]
        $Expand,

        [parameter(ParameterSetName = 'TableLogicalNameItemLookup')]
        [parameter(ParameterSetName = 'TableLogicalNameQuery')]
        [parameter(ParameterSetName = 'TableEntitySetNameItemLookup')]
        [parameter(ParameterSetName = 'TableEntitySetNameQuery')]
        [String[]]
        $Select,

        [parameter(Mandatory, ParameterSetName = 'TableLogicalNameQueryLegacy')]
        [parameter(Mandatory, ParameterSetName = 'TableEntitySetNameQueryLegacy')]
        [String]
        $FilterQuery,

        [parameter(ParameterSetName = 'TableLogicalNameQueryLegacy')]
        [parameter(ParameterSetName = 'TableEntitySetNameQueryLegacy')]
        [parameter(ParameterSetName = 'TableLogicalNameItemLookupLegacy')]
        [parameter(ParameterSetName = 'TableEntitySetNameItemLookupLegacy')]
        [string]
        $ExpandQuery,

        [parameter(ParameterSetName = 'TableLogicalNameQueryLegacy')]
        [parameter(ParameterSetName = 'TableEntitySetNameQueryLegacy')]
        [parameter(ParameterSetName = 'TableLogicalNameItemLookupLegacy')]
        [parameter(ParameterSetName = 'TableEntitySetNameItemLookupLegacy')]
        [String[]]
        $SelectFields

    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    if (($PSCmdlet.ParameterSetName).StartsWith('TableLogicalName')) {
        try {
            $EntitySet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')" -Select 'EntitySetName').EntitySetName
        }
        catch {
            throw "Cannot find table $Table in Dataverse Environment. $($_.InvocationInfo.MyCommand.Name),  $($_.InvocationInfo.InvocationName) , $($_.ToString())"
        }
    }


    if (($PSCmdlet.ParameterSetName).Contains(('Legacy'))) {
        Write-Warning "The ParameterSet $($PSCmdlet.ParameterSetName) is deprecated and will be removed in future releases. Please use -Select, -Filter and -Expand parameters instead of -SelectFields, -FilterQuery and -ExpandQuery"

        if ($PSBoundParameters.ContainsKey('SelectFields')) {
            $Select = $SelectFields
        }

        if ($PSBoundParameters.ContainsKey('FilterQuery')) {
            $Filter = $FilterQuery
        }

        if ($PSBoundParameters.ContainsKey('ExpandQuery')) {
            $Expand = $ExpandQuery
        }

    }


    $requestHeaders = @{'Prefer' = 'odata.include-annotations="*"' }

    if ($Select.Length -gt 0) {
        $selectQuery = '$select=' + ($Select -join ',')
    }

    #build the dv web query
    $dvRequestUri = [System.UriBuilder]::new($Global:DATAVERSEORGURL + "api/data/v9.2/$EntitySet")

    if ($PSBoundParameters.ContainsKey('ItemID')) {
        $dvRequestUri.Path += "($ItemID)"
    }

    if ($selectQuery.Length -gt 0) {
        $dvRequestUri.Query = $selectQuery
    }

    if ($Filter.Length -gt 0){
        if ($dvRequestUri.Query.Length -gt 0) {
            $dvRequestUri.Query += "&`$filter=$Filter"
        }
        else {
            $dvRequestUri.Query = "`$filter=$Filter"
        }
    }

    if ($Expand.Length -gt 0) {
        if ($dvRequestUri.Query.Length -gt 0) {
            $dvRequestUri.Query += "&`$expand=$Expand"
        }
        else {
            $dvRequestUri.Query = "`$expand=$Expand"
        }
    }

    return (Invoke-PSDVWebRequest -WebUri  $($dvRequestUri.Uri.AbsoluteUri) -Headers $requestHeaders)
}


function Get-PSDVTableItemAuditHistory {
    <#
    .SYNOPSIS
    Retrieves audit history for a specific Dataverse record.

    .DESCRIPTION
    Get-PSDVTableItemAuditHistory fetches the audit trail for a specific record in a Dataverse table.
    It returns audit information including who made changes, when changes were made, and what operations
    were performed. This function is useful for compliance, troubleshooting, and tracking data modifications.
    Auditing must be enabled on the table and fields for this function to return meaningful data.

    .PARAMETER Table
    The logical name of the Dataverse table containing the record.

    .PARAMETER ItemID
    The unique identifier (GUID) of the record to retrieve audit history for.

    .PARAMETER Select
    Array of audit field names to include in the response.

    .EXAMPLE
    Get-PSDVTableItemAuditHistory -Table "account" -ItemID "12345678-1234-1234-1234-123456789012"

    Retrieves all audit history for a specific account record.

    .EXAMPLE
    Get-PSDVTableItemAuditHistory -Table "contact" -ItemID "87654321-4321-4321-4321-210987654321" -Select @("createdon", "createdby", "operation")

    Retrieves specific audit fields for a contact record.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [String]
        $Table,

        [parameter()]
        [String]
        $ItemID,

        [parameter()]
        [String[]]
        $Select
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }


    Update-PSDVAccessToken

    $requestHeaders = @{'Prefer' = 'odata.include-annotations="*"' }

    $queryFilter = "objecttypecode eq '$Table' and _objectid_value eq '$ItemID'"

    if ($PSBoundParameters.ContainsKey('Select')) {
      $selectQuery = $Select -join ','
    }

    $dvRequestUri = $Global:DATAVERSEORGURL + 'api/data/v9.2/audits'

    $dvRequestUri += "?`$filter=$queryFilter"

    if ($selectQuery.Length -gt 0) {
        $dvRequestUri += "&`$select=$selectQuery"
    }

    return (Invoke-PSDVWebRequest -WebUri  $dvRequestUri -Headers $requestHeaders -Method 'Get')

}



function Get-PSDVTableItemChangeHistory {
    <#
    .SYNOPSIS
    Retrieves detailed change history for a specific Dataverse record.

    .DESCRIPTION
    Get-PSDVTableItemChangeHistory uses the RetrieveRecordChangeHistory API to fetch comprehensive
    change details for a specific record. Unlike audit history, this function provides detailed
    information about what specific field values were changed, including before and after values.
    This function requires auditing to be enabled and provides more granular change tracking.

    .PARAMETER Table
    The logical name of the Dataverse table containing the record.

    .PARAMETER EntitySet
    The entity set name of the Dataverse table (alternative to Table parameter).

    .PARAMETER ItemID
    The unique identifier (GUID) of the record to retrieve change history for.

    .EXAMPLE
    Get-PSDVTableItemChangeHistory -Table "account" -ItemID "12345678-1234-1234-1234-123456789012"

    Retrieves detailed change history for a specific account record.

    .EXAMPLE
    Get-PSDVTableItemChangeHistory -EntitySet "contacts" -ItemID "87654321-4321-4321-4321-210987654321"

    Retrieves change history using entity set name instead of logical name.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory, ParameterSetName = 'TableLogicalName')]
        [String]
        $Table,

        [parameter(Mandatory, ParameterSetName = 'TableEntitySetName')]
        [string]
        $EntitySet,

        [parameter(Mandatory)]
        [String]
        $ItemID
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    if (($PSCmdlet.ParameterSetName).StartsWith('TableLogicalName')) {
        try {
            $EntitySet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')" -Select 'EntitySetName').EntitySetName
        }
        catch {
            throw "Cannot find table $Table in Dataverse Environment. $($_.InvocationInfo.MyCommand.Name),  $($_.InvocationInfo.InvocationName) , $($_.ToString())"
        }
    }


    $requestHeaders = @{'Prefer' = 'odata.include-annotations="*"' }

    $dvRequestUri = $Global:DATAVERSEORGURL + "api/data/v9.2/RetrieveRecordChangeHistory(Target=@target)?@target={'@odata.id':'$EntitySet($ItemID)'}"

    $webResponse = Invoke-PSDVWebRequest -WebUri  $dvRequestUri -Headers $requestHeaders -Method 'Get'

    if ($webResponse.AuditDetailCollection.count -gt 0) {
        return $webResponse.AuditDetailCollection
    }
    else {
        return $webResponse
    }
}


function New-PSDVTableItem {
    <#
    .SYNOPSIS
    Creates a new record in a Dataverse table.

    .DESCRIPTION
    New-PSDVTableItem creates a new record in the specified Dataverse table using the provided data.
    It supports automatic field validation to ensure all provided fields exist in the target table.
    The function can optionally parse lookup relationships and convert them to the proper OData format.
    When ReturnItem is specified, it returns the created record with all server-generated values.

    .PARAMETER Table
    The logical name of the Dataverse table to create the record in.

    .PARAMETER EntitySet
    The entity set name of the Dataverse table (alternative to Table parameter).

    .PARAMETER ItemData
    Hashtable containing the field names and values for the new record.

    .PARAMETER ParseItemData
    When specified, automatically parses lookup field values and converts them to OData format.

    .PARAMETER ReturnItem
    When specified, returns the created record with server-generated values like ID and timestamps.

    .EXAMPLE
    $data = @{
        name = "Contoso Corporation"
        accountnumber = "ACC001"
        telephone1 = "555-123-4567"
    }
    New-PSDVTableItem -Table "account" -ItemData $data

    Creates a new account record with the specified data.

    .EXAMPLE
    $contactData = @{
        firstname = "John"
        lastname = "Doe"
        emailaddress1 = "john.doe@contoso.com"
        parentcustomerid = "12345678-1234-1234-1234-123456789012"
    }
    New-PSDVTableItem -Table "contact" -ItemData $contactData -ParseItemData -ReturnItem

    Creates a new contact with a lookup relationship, parses the lookup, and returns the created record.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory, ParameterSetName = 'TableLogicalName')]
        [String]
        $Table,

        [parameter(Mandatory, ParameterSetName = 'TableEntitySetName')]
        [string]
        $EntitySet,

        [parameter(Mandatory)]
        [System.Collections.Hashtable]
        $ItemData,

        [parameter()]
        [switch]
        $ParseItemData,

        [parameter()]
        [switch]
        $ReturnItem
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    #lookup table relationships require setting the Microsoft.Dynamics.CRM.associatednavigationproperty odata.bind = /entitysetname(item ID)
    # ex, "cr33a_MACOM@odata.bind" = "/cr33a_macoms(b7322079-55d2-ee11-9078-000d3a33b5cf)"

    if (($PSCmdlet.ParameterSetName).StartsWith('TableLogicalName')) {
        try {
            $EntitySet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')" -Select 'EntitySetName').EntitySetName
        }
        catch {
            throw "Cannot find table $Table in Dataverse Environment. $($_.InvocationInfo.MyCommand.Name),  $($_.InvocationInfo.InvocationName) , $($_.ToString())"
        }
    }


    $requestHeaders = @{
        'Prefer'       = 'odata.include-annotations="*"'
    }

    if ($ReturnItem.IsPresent) {
        $requestHeaders['Prefer'] = 'odata.include-annotations="*",return=representation'
    }

    #verify fields in ItemData are valid for the table
    if ($PSCmdlet.ParameterSetName.StartsWith('TableEntitySetName'))
    {
        $Table = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions?`$filter=EntitySetName eq '$EntitySet'&`$select=LogicalName").LogicalName
    }
    $tableColumns = Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')/Attributes"
    $attributeDetails = @{}
    $invalidAttributes = @()

    foreach ($attribute in $ItemData.GetEnumerator().name ) {
        if (! $tableColumns.LogicalName -contains $attribute) {
            $invalidAttributes += $attribute
        }else {
            $attributeDetails.Add($attribute, ($tableColumns | Where-Object { $_.LogicalName -eq $attribute } | Select-Object -Property AttributeType,SchemaName,Targets))
        }
    }
    if ($invalidAttributes.Count -gt 0) {
        throw "Invalid attributes not present in $Table : $($invalidAttributes -join ', ')"
    }
    


    if ($ParseItemData.IsPresent) {
        $ParsedItemData = @{}

        foreach ($attribute in $attributeDetails.GetEnumerator().name ) {
           if ($attributeDetails[$attribute].AttributeType -eq 'Lookup') {
                $navProperty = $attributeDetails[$attribute].SchemaName
                $targetTable = $attributeDetails[$attribute].Targets[0]
                $targetTableSet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$targetTable')" -Select 'EntitySetName').EntitySetName
                $targetItemID = $ItemData[$attribute]
                $ParsedItemData.Add("$navProperty@odata.bind", "/$targetTableSet($targetItemID)")
            }
            else {
                $ParsedItemData.Add($attribute, $ItemData[$attribute])
            }
        }

        $ItemData2Process = $ParsedItemData
    }
    else {
        $ItemData2Process = $ItemData
    }


    $dvRequestUri = $Global:DATAVERSEORGURL + "api/data/v9.2/$EntitySet"

    if ($PSCmdlet.ShouldProcess($EntitySet, "Create new item")) {
        return (Invoke-PSDVWebRequest -WebUri  $dvRequestUri -Headers $requestHeaders -Body $ItemData2Process)
    }

}


function Update-PSDVTableItem {
    <#
    .SYNOPSIS
    Updates an existing record in a Dataverse table.

    .DESCRIPTION
    Update-PSDVTableItem modifies an existing record in the specified Dataverse table using the provided data.
    It supports automatic field validation to ensure all provided fields exist in the target table.
    The function can optionally parse lookup relationships and convert them to the proper OData format.
    When ReturnItem is specified, it returns the updated record with current field values.
    Only the specified fields are updated; other fields remain unchanged.

    .PARAMETER Table
    The logical name of the Dataverse table containing the record to update.

    .PARAMETER EntitySet
    The entity set name of the Dataverse table (alternative to Table parameter).

    .PARAMETER ItemID
    The unique identifier (GUID) of the record to update.

    .PARAMETER ItemData
    Hashtable containing the field names and values to update in the record.

    .PARAMETER ParseItemData
    When specified, automatically parses lookup field values and converts them to OData format.

    .PARAMETER ReturnItem
    When specified, returns the updated record with current field values.

    .EXAMPLE
    $updateData = @{
        name = "Updated Company Name"
        telephone1 = "555-987-6543"
    }
    Update-PSDVTableItem -Table "account" -ItemID "12345678-1234-1234-1234-123456789012" -ItemData $updateData

    Updates an account record with new name and phone number.

    .EXAMPLE
    $contactUpdate = @{
        emailaddress1 = "newemail@contoso.com"
        parentcustomerid = "11111111-1111-1111-1111-111111111111"
    }
    Update-PSDVTableItem -Table "contact" -ItemID "87654321-4321-4321-4321-210987654321" -ItemData $contactUpdate -ParseItemData -ReturnItem

    Updates a contact's email and parent account, parses the lookup, and returns the updated record.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory, ParameterSetName = 'TableLogicalName')]
        [String]
        $Table,

        [parameter(Mandatory, ParameterSetName = 'TableEntitySetName')]
        [string]
        $EntitySet,

        [parameter()]
        [System.Guid]
        $ItemID,

        [parameter(Mandatory)]
        [System.Collections.Hashtable]
        $ItemData,

        [parameter()]
        [switch]
        $ParseItemData,

        [parameter()]
        [switch]
        $ReturnItem
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }

    #lookup table relationships require setting the Microsoft.Dynamics.CRM.associatednavigationproperty odata.bind = /entitysetname(item ID)
    # ex, "cr33a_MACOM@odata.bind" = "/cr33a_macoms(b7322079-55d2-ee11-9078-000d3a33b5cf)"

    if (($PSCmdlet.ParameterSetName).StartsWith('TableLogicalName')) {
        try {
            $EntitySet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')" -Select 'EntitySetName').EntitySetName
        }
        catch {
            throw "Cannot find table $Table in Dataverse Environment. $($_.InvocationInfo.MyCommand.Name),  $($_.InvocationInfo.InvocationName) , $($_.ToString())"
        }
    }


    $requestHeaders = @{
        'Prefer'       = 'odata.include-annotations="*"'
    }

    if ($ReturnItem.IsPresent) {
        $requestHeaders['Prefer'] = 'odata.include-annotations="*",return=representation'
    }

    #verify fields in ItemData are valid for the table
    if ($PSCmdlet.ParameterSetName.StartsWith('TableEntitySetName'))
    {
        $Table = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions?`$filter=EntitySetName eq '$EntitySet'&`$select=LogicalName").LogicalName
    }
    $tableColumns = Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')/Attributes"
    $attributeDetails = @{}
    $invalidAttributes = @()

    foreach ($attribute in $ItemData.GetEnumerator().name ) {
        if (! $tableColumns.LogicalName -contains $attribute) {
            $invalidAttributes += $attribute
        }else {
        $attributeDetails.Add($attribute, ($tableColumns | Where-Object { $_.LogicalName -eq $attribute } | Select-Object -Property AttributeType,SchemaName,Targets))
    }
    }
    if ($invalidAttributes.Count -gt 0) {
        throw "Invalid attributes not present in $Table : $($invalidAttributes -join ', ')"
    }
    


    if ($ParseItemData.IsPresent) {
        $ParsedItemData = @{}

        foreach ($attribute in $attributeDetails.GetEnumerator().name ) {
           if ($attributeDetails[$attribute].AttributeType -eq 'Lookup') {
                $navProperty = $attributeDetails[$attribute].SchemaName
                $targetTable = $attributeDetails[$attribute].Targets[0]
                $targetTableSet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$targetTable')" -Select 'EntitySetName').EntitySetName
                $targetItemID = $ItemData[$attribute]
                $ParsedItemData.Add("$navProperty@odata.bind", "/$targetTableSet($targetItemID)")
            }
            else {
                $ParsedItemData.Add($attribute, $ItemData[$attribute])
            }
        }

        $ItemData2Process = $ParsedItemData
    }
    else {
        $ItemData2Process = $ItemData
    }


    $dvRequestUri = $Global:DATAVERSEORGURL + "api/data/v9.2/$EntitySet($ItemID)"

    if ($PSCmdlet.ShouldProcess("$EntitySet($ItemID)", "Update item")) {
        return (Invoke-PSDVWebRequest -WebUri  $dvRequestUri -Headers $requestHeaders -Body $ItemData2Process -Method 'Patch' )
    }

}


function Remove-PSDVTableItem {
    <#
    .SYNOPSIS
    Deletes a record from a Dataverse table.

    .DESCRIPTION
    Remove-PSDVTableItem removes a specific record from the specified Dataverse table using the record's
    unique identifier. The function supports both logical name and entity set name parameter sets for
    table identification. Once deleted, the record cannot be recovered unless it's restored from a backup
    or the Dataverse recycle bin (if available and not expired).

    .PARAMETER Table
    The logical name of the Dataverse table containing the record to delete.

    .PARAMETER EntitySet
    The entity set name of the Dataverse table (alternative to Table parameter).

    .PARAMETER ItemID
    The unique identifier (GUID) of the record to delete.

    .EXAMPLE
    Remove-PSDVTableItem -Table "account" -ItemID "12345678-1234-1234-1234-123456789012"

    Deletes a specific account record by its ID.

    .EXAMPLE
    Remove-PSDVTableItem -EntitySet "contacts" -ItemID "87654321-4321-4321-4321-210987654321"

    Deletes a contact record using entity set name instead of logical name.

    .EXAMPLE
    Get-PSDVTableItem -Table "account" -Filter "name eq 'Test Account'" | ForEach-Object {
        Remove-PSDVTableItem -Table "account" -ItemID $_.accountid
    }

    Finds and deletes all accounts named "Test Account".
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param(
         [parameter(Mandatory, ParameterSetName = 'TableLogicalName')]
        [String]
        $Table,

        [parameter(Mandatory, ParameterSetName = 'TableEntitySetName')]
        [string]
        $EntitySet,

        [parameter(Mandatory)]
        [String]
        $ItemID
    )

    if ($null -eq $Global:DATAVERSEACCESSTOKEN) {
        throw 'No existing connection to Dataverse Environment, run Connect-PSDVOrg before executing other PSDV cmdlets'
    }


    if (($PSCmdlet.ParameterSetName).StartsWith('TableLogicalName')) {
        try {
            $EntitySet = (Invoke-PSDVWebRequest -WebUri "EntityDefinitions(LogicalName='$Table')" -Select 'EntitySetName').EntitySetName
        }
        catch {
            throw "Cannot find table $Table in Dataverse Environment. $($_.InvocationInfo.MyCommand.Name),  $($_.InvocationInfo.InvocationName) , $($_.ToString())"
        }
    }


    $requestHeaders = @{'Prefer' = 'odata.include-annotations="*"' }


    #build the dv web query
    $dvRequestUri = $Global:DATAVERSEORGURL + "api/data/v9.2/$EntitySet($ItemID)"

    if ($PSCmdlet.ShouldProcess("$EntitySet($ItemID)", "Delete item")) {
        return (Invoke-PSDVWebRequest -WebUri  $dvRequestUri -Headers $requestHeaders -Method 'Delete' )
    }
}

# Create aliases for backward compatibility
New-Alias -Name Delete-PSDVTableItem -Value Remove-PSDVTableItem -Force