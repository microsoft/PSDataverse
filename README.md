# Dataverse PowerShell Module

A comprehensive PowerShell module for interacting with Microsoft Dataverse environments. This module provides full CRUD operations, authentication management, and advanced querying capabilities for Dataverse tables and records.

## Features

- **Multiple Authentication Methods**: Support for Service Principal, Managed Identity, and Interactive authentication
- **Comprehensive CRUD Operations**: Create, Read, Update, and Delete operations for Dataverse records
- **Advanced Querying**: OData filters, field selection, record expansion, and automatic pagination
- **Metadata Operations**: Retrieve table and column metadata information
- **Audit and Change Tracking**: Access audit history and detailed change tracking
- **PowerShell 7.3+ Compatible**: Modern PowerShell support with Constrained Language Mode (CLM) compatibility
- **PSScriptAnalyzer Compliant**: Follows PowerShell best practices and coding standards

## Prerequisites

- PowerShell 7.3 or later
- Az.Accounts module 3.0.0 or later
- Appropriate permissions to access your Dataverse environment

## Installation

### Manual Installation

1. Download or clone this repository
2. Copy the `Dataverse` folder to one of your PowerShell module paths:
   - User modules: `$env:USERPROFILE\Documents\PowerShell\Modules\`
   - System modules: `$env:PROGRAMFILES\PowerShell\Modules\`

3. Import the module:
   ```powershell
   Import-Module Dataverse
   ```

### Verify Installation

```powershell
Get-Module Dataverse -ListAvailable
Get-Command -Module Dataverse
```

## Quick Start

### 1. Connect to Dataverse

#### Interactive Authentication
```powershell
Connect-PSDVOrg -AzureTenantId "your-tenant-id" `
                -SubscriptionId "your-subscription-id" `
                -DataverseOrgURL "https://yourorg.crm.dynamics.com/" `
                -Environment "AzureCloud"
```

#### Service Principal Authentication
```powershell
$secret = ConvertTo-SecureString "your-client-secret" -AsPlainText -Force
Connect-PSDVOrg -ClientID "your-client-id" `
                -ClientSecret $secret `
                -AzureTenantId "your-tenant-id" `
                -DataverseOrgURL "https://yourorg.crm.dynamics.com/" `
                -Environment "AzureCloud"
```

### 2. Basic Operations

#### Retrieve Records
```powershell
# Get all accounts
Get-PSDVTableItem -Table "account"

# Get specific account by ID
Get-PSDVTableItem -Table "account" -ItemID "12345678-1234-1234-1234-123456789012"

# Filter records
Get-PSDVTableItem -Table "contact" -Filter "firstname eq 'John'"

# Select specific fields
Get-PSDVTableItem -Table "account" -Select @("name", "telephone1", "websiteurl")
```

#### Create Records
```powershell
$accountData = @{
    name = "Contoso Corporation"
    accountnumber = "ACC001"
    telephone1 = "555-123-4567"
}
New-PSDVTableItem -Table "account" -ItemData $accountData
```

#### Update Records
```powershell
$updateData = @{
    name = "Updated Company Name"
    telephone1 = "555-987-6543"
}
Update-PSDVTableItem -Table "account" -ItemID "record-guid" -ItemData $updateData
```

#### Delete Records
```powershell
Remove-PSDVTableItem -Table "account" -ItemID "record-guid"
```

### 3. Metadata Operations

#### Get Table Information
```powershell
# Get all tables
Read-PSDVTableData

# Get detailed table metadata
Get-PSDVTableDetail -Table "account"

# Get column information
Get-PSDVTableColumn -Table "account"

# Get specific columns
Get-PSDVTableColumn -Table "account" -ColumnName @("name", "telephone1")
```

## Function Reference

### Connection Functions
- `Connect-PSDVOrg` - Establish connection to Dataverse
- `Update-PSDVAccessToken` - Refresh access token

### Core Operations
- `Invoke-PSDVWebRequest` - Execute authenticated web requests
- `Get-PSDVTableItem` - Retrieve records from tables
- `New-PSDVTableItem` - Create new records
- `Update-PSDVTableItem` - Update existing records
- `Remove-PSDVTableItem` - Delete records

### Metadata Functions
- `Read-PSDVTableData` - Get all table metadata
- `Get-PSDVTableDetail` - Get detailed table information
- `Get-PSDVTableColumn` - Get column metadata

### Audit Functions
- `Get-PSDVTableItemAuditHistory` - Get audit history
- `Get-PSDVTableItemChangeHistory` - Get detailed change history

## Advanced Examples

### Complex Filtering and Expansion
```powershell
# Get accounts with revenue over $1M and include primary contact
Get-PSDVTableItem -Table "account" `
                  -Filter "revenue gt 1000000" `
                  -Expand "primarycontactid" `
                  -Select @("name", "revenue", "primarycontactid")
```

### Working with Lookup Fields
```powershell
# Create contact with parent account lookup
$contactData = @{
    firstname = "John"
    lastname = "Doe"
    emailaddress1 = "john.doe@contoso.com"
    parentcustomerid = "account-guid"
}
New-PSDVTableItem -Table "contact" -ItemData $contactData -ParseItemData
```

### Audit Trail Analysis
```powershell
# Get complete audit history for a record
Get-PSDVTableItemAuditHistory -Table "account" -ItemID "record-guid"

# Get detailed change history
Get-PSDVTableItemChangeHistory -Table "account" -ItemID "record-guid"
```

## Error Handling

The module includes comprehensive error handling with meaningful error messages. Common patterns:

```powershell
try {
    $result = Get-PSDVTableItem -Table "account" -ItemID "invalid-guid"
}
catch {
    Write-Error "Failed to retrieve account: $($_.Exception.Message)"
}
```

## Security Considerations

- Use Service Principal authentication for automated scenarios
- Store secrets securely using PowerShell SecureString or Azure Key Vault
- Follow the principle of least privilege for Dataverse permissions
- The module is compatible with PowerShell Constrained Language Mode (CLM)

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Ensure correct tenant ID, client ID, and permissions
2. **Table Not Found**: Verify table logical names and case sensitivity
3. **Permission Denied**: Check Dataverse security roles and permissions
4. **Token Expiration**: The module automatically handles token refresh

### Verbose Logging
```powershell
# Enable verbose output for troubleshooting
Get-PSDVTableItem -Table "account" -Verbose
```

## Contributing

This module follows PowerShell best practices and PSScriptAnalyzer rules. When contributing:

1. Ensure PowerShell 7.3+ compatibility
2. Follow the existing code style and patterns
3. Include comprehensive help documentation
4. Test in both normal and Constrained Language Mode environments

## License

[Specify your license here]

## Support

[Specify support information here]

## Changelog

### Version 1.0.0
- Initial release
- Support for all major Dataverse operations
- Multiple authentication methods
- Comprehensive help documentation
- PSScriptAnalyzer compliance
- Constrained Language Mode compatibility