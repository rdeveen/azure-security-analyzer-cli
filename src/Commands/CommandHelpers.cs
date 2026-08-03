using AzureSecurityAnalyzer.Infrastructure;
using Spectre.Console;

namespace AzureSecurityAnalyzer.Commands;

/// <summary>
/// Shared validation and utility methods for commands.
/// </summary>
public static class CommandHelpers
{
    /// <summary>
    /// Resolves the subscription ID from settings or Azure CLI fallback.
    /// Returns a ValidationResult error if subscription is required but cannot be resolved.
    /// Sets the subscription on the settings if resolved from Azure CLI.
    /// </summary>
    public static ValidationResult ValidateAndResolveSubscription(Guid? subscription, bool isSubscriptionBased, Action<Guid> setSubscription)
    {
        if (!isSubscriptionBased || subscription.HasValue)
        {
            return ValidationResult.Success();
        }
        
        try
        {
            var resolved = Guid.Parse(AzCommand.GetDefaultAzureSubscriptionId());
            setSubscription(resolved);
            return ValidationResult.Success();
        }
        catch (Exception)
        {
            return ValidationResult.Error(
                "No subscription ID provided and unable to retrieve from Azure CLI. " +
                "Please specify a subscription ID using -s or --subscription, " +
                "or login to Azure CLI using 'az login'. Use --help for more information.");
        }
    }

    /// <summary>
    /// Prints version information when debug mode is enabled.
    /// </summary>
    public static void PrintVersionIfDebug(bool debug)
    {
        if (debug)
        {
            AnsiConsole.WriteLine($"Version: {typeof(CommandHelpers).Assembly.GetName().Version}");
        }
    }
}