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
