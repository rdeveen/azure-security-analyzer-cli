# azure-security-analyzer-cli

Azure Security Analyzer CLI

## Installation

### Prerequisites

- .NET 10.0 runtime
- Azure CLI authenticated (`az login`) or an Azure identity with minimal the Reader role

## Authentication

To make the call to the Azure Management API, you do need to run this from a user account with permissions to access the resources of the subscription. Further more, it needs to find the active credentials and it does so by using the ChainedTokenCredential provider which will look for the az cli token first. Make sure to run az login (with optionally the --tenant parameter) to make sure you have an active session.

## Global flags

These flags are available on every command:

| Flag | Description |
|------|-------------|
| `--no-color` | Disable ANSI color and escape codes. Useful when piping output to files or running in CI environments where color codes appear as garbage. |
| `--quiet` | Suppress all status spinners and progress messages. Only the actual data output is written. Useful for scripting or when redirecting output. |
| `--debug` | Show verbose debug information including resolved subscription IDs and API calls. |

**Examples:**

```bash
# Run the regions command with no color and quiet mode
az-security-analyzer regions --no-color --quiet
```

## Commands

| Command | Description |
|---------|-------------|
| `regions` | Get the available Azure regions. This is also the default command when no command is specified. |
| `nsg` | Get the network security groups in the subscription. |
| `advisor` | Get the Azure Advisor recommendations for the subscription. |

## Common options

These options are available on all commands:

| Option | Description |
|--------|-------------|
| `-s`, `--subscription` | The subscription id to use. Will try to fetch the active id if not specified. |
| `-o`, `--output` | The output format to use. Defaults to `Console` (`Console`, `Json`, `JsonC`, `Text`, `Markdown`, `Csv`). |
| `--skipHeader` | Skip header creation for specific output formats. Useful when appending the output from multiple runs into one file. Defaults to false. |
| `--httpTimeout` | Allows overriding the default HTTP timeout in seconds. Defaults to 100 seconds. |

## Examples

### Regions

```bash
# List the available Azure regions (also the default command)
az-security-analyzer regions

# List the regions in JSON format
az-security-analyzer regions --output Json

# List the regions in Markdown format, e.g. for use in a GitHub Actions job summary
az-security-analyzer regions --output Markdown >> $GITHUB_STEP_SUMMARY
```

### Network security groups

```bash
# List the network security groups in the active subscription
az-security-analyzer nsg

# List the network security groups in a specific subscription
az-security-analyzer nsg --subscription 00000000-0000-0000-0000-000000000000

# Export the network security groups to a CSV file
az-security-analyzer nsg --output Csv > nsg.csv
```

### Advisor recommendations

```bash
# Get the Azure Advisor recommendations for the active subscription
az-security-analyzer advisor

# Get the recommendations for a specific subscription
az-security-analyzer advisor --subscription 00000000-0000-0000-0000-000000000000

# Scope the recommendations to a specific resource group (requires the subscription id)
az-security-analyzer advisor --subscription 00000000-0000-0000-0000-000000000000 --resource-group my-resource-group

# Output the recommendations as JSON, e.g. for further processing with jq
az-security-analyzer advisor --output Json --quiet | jq '.'
```

### Scripting and CI

```bash
# Disable colors and status messages when redirecting output to a file
az-security-analyzer nsg --no-color --quiet --output Text > nsg.txt

# Append the output from multiple runs into one file, skipping repeated headers
az-security-analyzer advisor --subscription 00000000-0000-0000-0000-000000000000 --output Csv > report.csv
az-security-analyzer advisor --subscription 11111111-1111-1111-1111-111111111111 --output Csv --skipHeader >> report.csv

# Increase the HTTP timeout for large subscriptions
az-security-analyzer advisor --httpTimeout 300

# Show verbose debug information, such as the resolved subscription id and API calls
az-security-analyzer nsg --debug
```
