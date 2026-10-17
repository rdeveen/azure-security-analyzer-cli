using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.VirtualNetworkPeerings;

public class Command(IAzureResourceRetriever azureResourceRetriever) : AsyncCommand<Settings>
{
    private readonly IAzureResourceRetriever azureResourceRetriever = azureResourceRetriever;
    private readonly Dictionary<OutputFormat, BaseOutputFormatter> outputFormatters = OutputFormatterFactory.Create();

    public override ValidationResult Validate(CommandContext context, Settings settings)
    {
        var result = CommandHelpers.ValidateAndResolveSubscription(
            settings.Subscription, isSubscriptionBased: true, s => settings.Subscription = s);

        return result.Successful ? base.Validate(context, settings) : result;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        CommandHelpers.PrintVersionIfDebug(settings.Debug);

        azureResourceRetriever.ManagementApiAddress = settings.ManagementApiAddress;
        azureResourceRetriever.HttpTimeout = TimeSpan.FromSeconds(settings.HttpTimeout);

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching virtual networks...", async ctx =>
        {
            var virtualNetworks = await azureResourceRetriever.RetrieveVirtualNetworks(
                settings.Debug, settings.Subscription!.Value);

            ctx.Status = $"Retrieved {virtualNetworks.Count} virtual networks.";

            var analysisResults = await Analyzer.Analyze(virtualNetworks);

            await outputFormatters[settings.Output]
                .WriteVirtualNetworkPeerings(settings, virtualNetworks, analysisResults);
        });

        return 0;
    }
}
