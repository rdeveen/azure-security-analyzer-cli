using System.ComponentModel;
using AzureSecurityAnalyzer.Infrastructure;
using Spectre.Console;
// using AzureSecurityAnalyzer.Commands.AccumulatedCost;
// using AzureSecurityAnalyzer.Commands.Budgets;
// using AzureSecurityAnalyzer.Commands.CostByResource;
// using AzureSecurityAnalyzer.Commands.CostByTag;
// using AzureSecurityAnalyzer.Commands.DailyCost;
// using AzureSecurityAnalyzer.Commands.DetectAnomaly;
// using AzureSecurityAnalyzer.Commands.Diff;
// using AzureSecurityAnalyzer.Commands.Regions;
// using AzureSecurityAnalyzer.Commands.Threshold;
// using AzureSecurityAnalyzer.Commands.WhatIf;
// using AzureSecurityAnalyzer.CostApi;
// using AzureSecurityAnalyzer.Infrastructure.TypeConvertors;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using AzureSecurityAnalyzer.RegionsApi;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.Commands;

// Apply --no-color early from CLI args, before any Spectre output is rendered.
// The ConfigFileInterceptor also applies NoColor after command settings are parsed,
// covering the case where --no-color comes from the config file or settings.NoColor is set.
if (args.Contains("--no-color"))
{
    AnsiConsole.Profile.Capabilities.ColorSystem = ColorSystem.NoColors;
    AnsiConsole.Profile.Capabilities.Ansi = false;
}

// Setup the DI
var registrations = new ServiceCollection();

// Register a http client so we can make requests to the Azure Management API
registrations.AddHttpClient("ManagementApi", client =>
{
    client.BaseAddress = new Uri("https://management.azure.com/");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
}).AddPolicyHandler(PollyExtensions.GetRetryAfterPolicy());
 
registrations.AddHttpClient("RegionsApi", client =>
{
    client.BaseAddress = new Uri("https://datacenters.microsoft.com/");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.DefaultRequestHeaders.Add("User-Agent", "azure-cost-cli");
}).AddPolicyHandler(PollyPolicyExtensions.GetRetryAfterPolicy());

registrations.AddTransient<IAzureResourceRetriever, AzureResourceRetriever>(); 
registrations.AddTransient<IRegionsRetriever, AzureRegionsRetriever>();

var registrar = new TypeRegistrar(registrations);

// Setup the application itself
var app = new CommandApp(registrar);

// We default to the ShowCommand
app.SetDefaultCommand<AzureSecurityAnalyzer.Commands.Regions.Command>();

app.Configure(config =>
{
    config.SetApplicationName("azure-security-analyzer");
    config.UseAssemblyInformationalVersion();
    //     config.SetInterceptor(new ConfigFileInterceptor());

    config.AddExample(["regions"]);

    config.AddCommand<AzureSecurityAnalyzer.Commands.Regions.Command>("regions")
       .WithDescription("Get the available Azure regions.");

    config.AddExample(["nsg"]);

    config.AddCommand<AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Command>("nsg")
       .WithDescription("Get the network security groups in the subscription.");

    //         .WithDescription("Show the accumulated cost details.");
    //     config.AddExample(new[] { "accumulatedCost", "-o", "json" });
    //     config.AddExample(new[] { "costByResource", "-s", "00000000-0000-0000-0000-000000000000", "-o", "text" });
    //     config.AddExample(new[] { "dailyCosts", "--dimension", "MeterCategory" });
    //     config.AddExample(new[] { "budgets", "-s", "00000000-0000-0000-0000-000000000000" });
    //     config.AddExample(new[] { "detectAnomalies", "--dimension", "ResourceId", "--recent-activity-days", "4" });
    //     config.AddExample(new[] { "costByTag", "--tag", "cost-center" });

    // config.SetExceptionHandler((ex, resolver) =>
    // {
    //     // CommandRuntimeException wraps validation errors (e.g. ValidationResult.Error).
    //     // Print only the message — the stack trace is internal Spectre machinery, not useful to the user.
    //     if (ex is Spectre.Console.Cli.CommandRuntimeException)
    //     {
    //         Console.Error.WriteLine($"Error: {ex.Message}");
    //     }
    //     else
    //     {
    //         Console.Error.WriteLine(ex);
    //     }
    //     return -1;
    // });

    //     config.AddCommand<AccumulatedCostCommand>("accumulatedCost")
    //         .WithDescription("Show the accumulated cost details.");

    //     config.AddCommand<DailyCostCommand>("dailyCosts")
    //       .WithDescription("Show the daily cost by a given dimension.");

    //     config.AddCommand<CostByResourceCommand>("costByResource")
    //       .WithDescription("Show the cost details by resource.");

    //     config.AddCommand<CostByTagCommand>("costByTag")
    //       .WithDescription("Show the cost details by the provided tag key(s).");

    //     config.AddCommand<DetectAnomalyCommand>("detectAnomalies")
    //       .WithDescription("Detect anomalies and trends.");

    //     config.AddCommand<DiffCommand>("diff")
    //       .WithDescription("Show the cost difference between two timeframes.");

    //     config.AddCommand<BudgetsCommand>("budgets")
    //       .WithDescription("Get the available budgets.");

    //     config.AddBranch<WhatIfSettings>("what-if", add =>
    //     {
    //         add.AddCommand<DevTestWhatIfCommand>("devtest").WithDescription("Run what-if scenarios to check price differences if the resources were on a DevTest subscription. Only applies to VMs.");
    //         add.AddCommand<RegionWhatIfCommand>("region").WithDescription("Run what-if scenarios to check price differences if the resources would have run in a different region. Only applies to VMs.");
    //         add.SetDescription("Run what-if scenarios");
    //     });

    //     config.AddCommand<RegionsCommand>("regions")
    //       .WithDescription("Get the available Azure regions.");

    //     config.AddBranch("threshold", add =>
    //     {
    //         add.AddCommand<DailyChangeThresholdCommand>("daily-change")
    //         .WithDescription("Trigger if today's cost change vs yesterday exceeds the threshold.");
    //         add.AddCommand<ForecastDeviationThresholdCommand>("forecast-deviation")
    //         .WithDescription("Trigger if actual spend deviates from forecast by more than the threshold.");
    //         add.AddCommand<ServiceSpikeThresholdCommand>("service-spike")
    //         .WithDescription("Trigger if any single service cost spikes beyond the threshold vs the previous period.");
    //         add.AddCommand<WeeklyAverageThresholdCommand>("weekly-average")
    //         .WithDescription("Trigger if the 7-day average daily cost exceeds the threshold.");
    //         add.SetDescription("Cost threshold checks for CI/CD gating.");
    //     });

    config.ValidateExamples();
});

// Run the application
return await app.RunAsync(args);