using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;

public class Command(IAzureResourceRetriever azureResourceRetriever) : AsyncCommand<Settings>
{
    private readonly IAzureResourceRetriever azureResourceRetriever = azureResourceRetriever;
    private readonly Dictionary<OutputFormat, BaseOutputFormatter> outputFormatters = OutputFormatterFactory.Create();

    protected override ValidationResult Validate(CommandContext context, Settings settings)
    {
        var result = CommandHelpers.ValidateAndResolveSubscription(
            settings.Subscription, isSubscriptionBased: true, s => settings.Subscription = s);

        return result.Successful ? base.Validate(context, settings) : result;
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        CommandHelpers.PrintVersionIfDebug(settings.Debug);

        azureResourceRetriever.ManagementApiAddress = settings.ManagementApiAddress;
        azureResourceRetriever.HttpTimeout = TimeSpan.FromSeconds(settings.HttpTimeout);

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching network security groups...", async ctx =>
        {
            var networkSecurityGroups = await azureResourceRetriever.RetrieveNetworkSecurityGroups(
                settings.Debug, settings.Subscription!.Value);

            ctx.Status = $"Retrieved {networkSecurityGroups.Count} network security groups.";
            
            var analysisResults = await Analyzer.Analyze(networkSecurityGroups);

            // Write the output
            await outputFormatters[settings.Output]
                .WriteNetworkSecurityGroups(settings, networkSecurityGroups, analysisResults);
        });

        return 0;
    }
}
