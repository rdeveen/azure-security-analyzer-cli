using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.AzureFirewalls;

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

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching Azure firewalls...", async ctx =>
        {
            var azureFirewalls = await azureResourceRetriever.RetrieveAzureFirewalls(
                settings.Debug, settings.Subscription!.Value);

            ctx.Status = $"Retrieved {azureFirewalls.Count} Azure firewalls. Fetching firewall policies...";

            var firewallPolicies = await azureResourceRetriever.RetrieveFirewallPolicies(
                settings.Debug, settings.Subscription.Value);

            var ruleCollectionGroupTasks = firewallPolicies.ToDictionary(
                p => p.Id,
                p => azureResourceRetriever.RetrieveFirewallPolicyRuleCollectionGroups(
                    settings.Debug,
                    settings.Subscription.Value,
                    p.GetResourceGroupName(),
                    p.Name));

            await Task.WhenAll(ruleCollectionGroupTasks.Values);

            var ruleCollectionGroupsByPolicyId = ruleCollectionGroupTasks.ToDictionary(
                kvp => kvp.Key,
                kvp => (IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>)kvp.Value.Result);

            ctx.Status = $"Retrieved {firewallPolicies.Count} firewall policies.";

            var analysisResults = await Analyzer.Analyze(firewallPolicies, azureFirewalls, ruleCollectionGroupsByPolicyId);

            await outputFormatters[settings.Output]
                .WriteAzureFirewalls(settings, firewallPolicies, azureFirewalls, ruleCollectionGroupsByPolicyId, analysisResults);
        });

        return 0;
    }
}
