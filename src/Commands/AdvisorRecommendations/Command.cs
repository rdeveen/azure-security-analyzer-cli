using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.AdvisorRecommendations;

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

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching advisor recommendations...", async ctx =>
        {
            var recommendations = await azureResourceRetriever.RetrieveAdvisorRecommendations(
                settings.Debug, settings.Subscription!.Value, settings.GetScope);

            ctx.Status = $"Retrieved {recommendations.Count} advisor recommendations.";

            ctx.Status = "Fetching Microsoft Defender for Cloud recommendations...";

            var defenderRecommendations = await azureResourceRetriever.RetrieveDefenderForCloudRecommendations(
                settings.Debug, settings.Subscription!.Value, settings.GetScope);

            ctx.Status = $"Retrieved {defenderRecommendations.Count} Microsoft Defender for Cloud recommendations.";

            ctx.Status = "Fetching Microsoft Defender for Cloud security policies...";

            var securityPolicies = await azureResourceRetriever.RetrieveDefenderForCloudSecurityPolicies(
                settings.Debug, settings.Subscription!.Value);

            ctx.Status = $"Retrieved {securityPolicies.Count} Microsoft Defender for Cloud security policies.";

            // Write the output
            await outputFormatters[settings.Output]
                .WriteAdvisorRecommendations(settings, [.. recommendations, .. defenderRecommendations]);

            await outputFormatters[settings.Output]
                .WriteSecurityPolicies(settings, securityPolicies);
        });

        return 0;
    }
}
