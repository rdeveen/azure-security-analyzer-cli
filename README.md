# azure-security-analyzer-cli

Azure Security Analyzer CLI

## Installation

### Prerequisites

- .NET 10.0 runtime
- Azure CLI authenticated (`az login`) or an Azure identity with minimal the Reader role

## Authentication

To make the call to the Azure Management API, you do need to run this from a user account with permissions to access the resources of the subscription. Further more, it needs to find the active credentials and it does so by using the ChainedTokenCredential provider which will look for the az cli token first. Make sure to run `az login` (with optionally the --tenant parameter) to make sure you have an active session.

## Commands

### The following commands are available

| Command                        | Description                                                                       |
| ------------------------------ | --------------------------------------------------------------------------------- |
| `az-security-analyzer regions` | List all Azure regions and their availability.          |
| `az-security-analyzer nsg`     | Analyze Network Security Groups (NSGs) for security issues and misconfigurations. |
| `az-security-analyzer route-tables` | Analyze route tables for default-route and attachment issues. |
| `az-security-analyzer advisor` | Analyze Azure Advisor recommendations for security-related issues.                |
| `az-security-analyzer --help`  | Show help information for the Azure Security Analyzer CLI.                        |

## Global flags

These flags are available on every command:

| Flag         | Description                                                                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `--no-color` | Disable ANSI color and escape codes. Useful when piping output to files or running in CI environments where color codes appear as garbage.   |
| `--quiet`    | Suppress all status spinners and progress messages. Only the actual data output is written. Useful for scripting or when redirecting output. |
| `--debug`    | Show verbose debug information including resolved subscription IDs and API calls.                                                            |
| `--output`   | Specify the output format. Options include `Json`, `JsonC` (json in color), `Markdown`, `Console`, etc. Default is `Console`.                |

**Examples:**

```bash
# Run the regions command with no color and quiet mode
az-security-analyzer regions --no-color --quiet

# Run the security-analyzer with NSG analysis
az-security-analyzer nsg

# Run the security-analyzer with Advisor recommendations
az-security-analyzer advisor

# Run the security-analyzer with route table analysis
az-security-analyzer route-tables
```
