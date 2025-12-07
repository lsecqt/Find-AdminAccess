# FindAdminAccess

A C# utility that enumerates domain computers and tests administrative access to them, including connectivity checks, admin privileges verification, and C$ share writability testing.

## Features

- Enumerate all computers in an Active Directory domain
- Test network connectivity
- Verify administrative access using Service Control Manager (SCM) API
- Test C$ administrative share writability
- Support for both synchronous and asynchronous processing
- Flexible domain and domain controller specification
- Single computer testing mode

## Requirements

- .NET Framework (or .NET Core/5+)
- Windows operating system
- Domain-joined machine or domain credentials
- Appropriate Active Directory query permissions
- Administrative rights on target computers (to verify access)

## Usage

### Basic Syntax

```bash
FindAdminAccess.exe [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--async` | Process computers asynchronously for faster execution |
| `--domain <name>` | Specify domain name (e.g., contoso.com) |
| `--dc <server>` | Specify domain controller to query |
| `--computer <name>` | Test a specific computer only |
| `--help`, `-h`, `/?` | Show help message |

### Examples

Test all computers in the current domain (synchronous):
```bash
FindAdminAccess.exe
```

Test all computers asynchronously (faster but resources heavy):
```bash
FindAdminAccess.exe --async
```

Specify domain and domain controller:
```bash
FindAdminAccess.exe --domain contoso.com --dc dc01.contoso.com
```

Test a specific computer:
```bash
FindAdminAccess.exe --computer SERVER01 --async
```

## Output

The tool displays results in a table format:

```
Computer Name                  Online          Admin Handle    C$ Writable
---------------------------------------------------------------------------
SERVER01.contoso.com           Yes             Yes             Yes
WORKSTATION02.contoso.com      Yes             No              N/A
OFFLINE-PC.contoso.com         No              N/A             N/A
```

### Column Descriptions

- **Computer Name**: FQDN of the computer
- **Online**: Whether the computer responds to ping
- **Admin Handle**: Whether administrative access (SCM) is available
- **C$ Writable**: Whether the administrative C$ share is writable

## How It Works

1. **Computer Enumeration**: Queries Active Directory using `PrincipalContext` and `ComputerPrincipal` to retrieve all computer objects
2. **Connectivity Check**: Uses ICMP ping with 1-second timeout to verify network connectivity
3. **Admin Access Test**: Attempts to open Service Control Manager with `SC_MANAGER_ALL_ACCESS` rights via P/Invoke
4. **C$ Share Test**: Tries to create and delete a test file on the administrative C$ share

## Building

### Visual Studio
1. Open the solution in Visual Studio
2. Build the project (Ctrl+Shift+B)

### Command Line
```bash
csc /out:FindAdminAccess.exe Program.cs
```

Or with .NET CLI:
```bash
dotnet build
```

## Troubleshooting

If you encounter domain connection errors, try these steps:

1. Verify DNS resolution of the domain/DC
2. Check if LDAP ports (389/636/3268/3269) are accessible
3. Try using just `--dc` without `--domain` parameter
4. Try using the DC's FQDN instead of IP address
5. Ensure you have domain query permissions

## Notes

- Local machine testing is in the TODO
- Async mode significantly increases performance for large domains
- Failed admin access attempts do not generate verbose errors by default (can be enabled in code)


## Author

Lsecqt
