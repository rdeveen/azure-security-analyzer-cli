# Copilot instructions

.NET CLI (`azure-security-analyzer`, packaged as a dotnet tool) that reads Azure resources via the Management REST API and flags security misconfigurations. Built on Spectre.Console.Cli. Multi-targets `net10.0` and `net11.0` (preview SDK; see `.devcontainer`).

## Build, test, run

Run from `src\` (build/run) or `tests\` (test), as CI does. Always pass `--framework` since both projects multi-target.

```bash
dotnet build src --framework net10.0
dotnet test tests --framework net10.0
dotnet test tests --framework net10.0 --filter "FullyQualifiedName~RouteTables.AnalyzerTests"   # subset
dotnet test tests --framework net10.0 --filter "FullyQualifiedName=AzureSecurityAnalyzer.Tests.Commands.RouteTables.CommandTests.ExecuteAsync_CallsResourceRetriever_Once"   # single test
dotnet run --project src --framework net10.0 -- nsg -s <subscription-id> -o markdown
```

No separate lint step. CI "run" job executes every command (`nsg, advisor, route-tables, firewall, vnet-peerings`) against a real subscription with `-o markdown --quiet`. Releases are triggered by pushing a tag (tag name becomes the package version).

## Architecture

- `src\Program.cs` wires DI (`ServiceCollection` → custom `TypeRegistrar`/`TypeResolver` for Spectre), registers a named `ManagementApi` `HttpClient` with a Polly retry-after policy, and registers each command by name. Default command is `advisor`. A global exception handler writes to **stderr** and returns exit code 1.
- `src\Commands\<Feature>\` – one folder per command, each with `Command.cs`, `Settings.cs`, and (except Advisor) `Analyzer.cs`. Namespace is `AzureSecurityAnalyzer.Commands.<Feature>`, so each feature has its own `Command`, `Settings`, `Analyzer`, `AnomalyDetectionResult` types.
- Command flow: `Validate` resolves the subscription (`CommandHelpers.ValidateAndResolveSubscription`, falls back to `az` CLI default) → `ExecuteAsync` sets `ManagementApiAddress`/`HttpTimeout` on the retriever → fetch inside `AnsiConsoleExt.StatusAsync` (spinner suppressed by `--quiet`) → `Analyzer.Analyze(...)` → `outputFormatters[settings.Output].WriteXxx(...)`.
- Analyzers are static lists of private `I...AnomalyRule` implementations; each `TryDetect` returns an `AnomalyDetectionResult` (with a `SeverityLevel`) or `null`. Add a rule by appending to the `Rules` list.
- `src\ManagementApi\AzureResourceRetriever.cs` – `IAzureResourceRetriever` is the single seam to Azure (ARM models + paged `nextLink` retrieval; debug mode dumps JSON). Commands depend only on the interface so tests mock it.
- `src\OutputFormatters\` – `BaseOutputFormatter` has one abstract `Write<Feature>` method per command; implemented by Console, Json (also used for `Jsonc`) and Markdown formatters, registered in `OutputFormatterFactory`. `OutputFormat` values `Text`/`Csv` exist but have no formatter (commented out in the factory).
- Settings inherit `CommandSettings` → `LogCommandSettings` (`LogCommandSettings`: `--no-color`, `--quiet`, `--debug`; `CommandSettings`: `-s`, `-o`, `--managementApiAddress`, `--httpTimeout`, `--skipHeader`).
- `infra\*.bicep` deploys test resources (NSG, firewall, peerings) used by the CI integration run (`infra.yml`).

## Adding a new command

Touch all of: new `Commands\<Feature>\` folder, `IAzureResourceRetriever` + `AzureResourceRetriever` method, new abstract `Write<Feature>` in `BaseOutputFormatter` and **all** formatter implementations, registration + `AddExample` in `Program.cs` (`config.ValidateExamples()` runs at startup, so a bad example breaks the whole app), README command table, and the CI `run` matrix in `build.yml`. Add useful samples to the `infra\*.bicep` files as well.

## Conventions

- Tests (xunit + AwesomeAssertions + Moq) mirror the `src` layout under `tests\`. `src` exposes internals to the test project via `InternalsVisibleTo`.
- Command tests use `Mock<IAzureResourceRetriever>(MockBehavior.Strict)` with `SetupAllProperties()`, and are tagged `[Collection("ConsoleOutputTests")]` because they capture the global `AnsiConsole`; keep new console-capturing tests in that collection to avoid parallel interference.
- Package versions differ per TFM (`Microsoft.Extensions.*` 10.x vs 11.0 RC) via `Condition="'$(TargetFramework)' == ..."`; keep both lines in sync when bumping (in both csprojs).
- `--no-color` is applied in `Program.cs` before any Spectre output; don't print before that.
- Primary-constructor style (`class Command(IAzureResourceRetriever r)`) is used for commands and the retriever.
