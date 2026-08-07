using System.ComponentModel;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.AdvisorRecommendations;

public class Settings : CostSettings
{
    [CommandOption("-g|--resource-group")]
    [Description("The resource group to scope the request to. Need to be used in combination with the subscription id.")]
    public string? ResourceGroup { get; set; }

    public override Scope GetScope
    {
        get {
            if (Subscription != null && !string.IsNullOrWhiteSpace(ResourceGroup))
            {
                return Scope.ResourceGroup(Subscription.Value, ResourceGroup);
            }
            else // default to subscription
            {
                return Scope.Subscription(Subscription.GetValueOrDefault(Guid.Empty));
            }
        }
    }
}
