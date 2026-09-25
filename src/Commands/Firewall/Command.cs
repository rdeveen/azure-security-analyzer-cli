using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.Firewall;

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

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching firewall policies...", async ctx =>
        {
            var firewallPolicies = await azureResourceRetriever.RetrieveFirewallPolicies(
                settings.Debug, settings.Subscription!.Value);

            ctx.Status = $"Retrieved {firewallPolicies.Count} firewall policies.";

            var analysisResults = await Analyzer.Analyze(firewallPolicies);

            // Write the output
            await outputFormatters[settings.Output]
                .WriteFirewallPolicies(settings, firewallPolicies, analysisResults);
        });

        return 0;
    }
}
