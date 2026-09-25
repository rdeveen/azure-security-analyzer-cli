using AzureSecurityAnalyzer.Infrastructure;
using Spectre.Console;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using AzureSecurityAnalyzer.ManagementApi;

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
 
registrations.AddTransient<IAzureResourceRetriever, AzureResourceRetriever>(); 

var registrar = new TypeRegistrar(registrations);

// Setup the application itself
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("azure-security-analyzer");
    config.UseAssemblyInformationalVersion();

    config.AddExample(["nsg", "--subscription", "<subscription-id>", "--output", "markdown"]);

    config.AddCommand<AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Command>("nsg")
       .WithDescription("Get the network security groups in the subscription.");

    config.AddCommand<AzureSecurityAnalyzer.Commands.AzureFirewalls.Command>("firewall")
       .WithDescription("Get the Azure Firewall policies in the subscription.");

    config.AddExample(["firewall"]);

    config.AddCommand<AzureSecurityAnalyzer.Commands.RouteTables.Command>("route-tables")
       .WithDescription("Get the route tables in the subscription.");

    config.AddExample(["route-tables"]);

    config.AddCommand<AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Command>("advisor")
       .WithDescription("Get the Azure Advisor recommendations for the subscription.");

    config.AddExample(["advisor"]);

    // Without an exception handler, Spectre.Console.Cli writes the exception to stdout
    // and returns -1, which the shell reports as exit code 255. Write to stderr instead,
    // so the error stays visible when stdout is redirected (e.g. >> $GITHUB_STEP_SUMMARY),
    // and return 1 as a conventional failure exit code.
    config.SetExceptionHandler((ex, resolver) =>
    {
        // CommandRuntimeException wraps validation errors (e.g. ValidationResult.Error).
        // Print only the message — the stack trace is internal Spectre machinery, not useful to the user.
        if (ex is Spectre.Console.Cli.CommandRuntimeException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
        else
        {
            Console.Error.WriteLine(ex);
        }
        return 1;
    });
    config.ValidateExamples();
});

// Run the application
return await app.RunAsync(args);