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

            var remoteVirtualNetworks = new List<VirtualNetwork>();
            var unavailableRemoteVirtualNetworkIds = new List<string>();
            var remoteVirtualNetworkIds = virtualNetworks
                .SelectMany(network => network.Properties.VirtualNetworkPeerings ?? [])
                .Select(peering => peering.Properties.RemoteVirtualNetwork?.Id)
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var remoteVirtualNetworkId in remoteVirtualNetworkIds)
            {
                if (virtualNetworks.Any(network => string.Equals(
                        network.Id, remoteVirtualNetworkId, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                try
                {
                    var remoteVirtualNetwork = await azureResourceRetriever.RetrieveVirtualNetwork(
                        settings.Debug, remoteVirtualNetworkId!);
                    if (remoteVirtualNetwork is not null)
                    {
                        remoteVirtualNetworks.Add(remoteVirtualNetwork);
                    }
                    else
                    {
                        unavailableRemoteVirtualNetworkIds.Add(remoteVirtualNetworkId!);
                    }
                }
                catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
                {
                    unavailableRemoteVirtualNetworkIds.Add(remoteVirtualNetworkId!);
                }
            }

            var analysisResults = await Analyzer.Analyze(
                virtualNetworks, remoteVirtualNetworks, unavailableRemoteVirtualNetworkIds);

            await outputFormatters[settings.Output]
                .WriteVirtualNetworkPeerings(settings, virtualNetworks, analysisResults);
        });

        return 0;
    }
}
