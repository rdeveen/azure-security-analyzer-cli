using System.ComponentModel;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands;

public interface ICommandSettings
{
    bool SkipHeader { get; set; }
    OutputFormat Output { get; set; }
}

public class CommandSettings : LogCommandSettings, ICommandSettings
{
    [CommandOption("-s|--subscription")]
    [Description("The subscription id to use. Will try to fetch the active id if not specified.")]
    public Guid? Subscription { get; set; }

    [CommandOption("-o|--output")]
    [Description("The output format to use. Defaults to Console (Console, Json, JsonC, Text, Markdown, Csv)")]
    public OutputFormat Output { get; set; } = OutputFormat.Console;

    [CommandOption("--skipHeader")]
    [Description("Skip header creation for specific output formats. Useful when appending the output from multiple runs into one file. Defaults to false.")]
    [DefaultValue(false)]
    public bool SkipHeader { get; set; }

    [CommandOption("--managementApiAddress <BASE_ADDRESS>")]
    [Description("The base address for the Management API. Defaults to https://management.azure.com/")]
    public string ManagementApiAddress { get; set; } = "https://management.azure.com/";

    [CommandOption("--httpTimeout <TIMEOUT>")]
    [Description("Allows overriding the default HTTP timeout in seconds. Defaults to 100 seconds.")]
    public int HttpTimeout { get; set; } = 100;

    public virtual Scope GetScope
    {
        get
        {
            return Scope.Subscription(Subscription.GetValueOrDefault(Guid.Empty));
        }
    }
}

/// <summary>
/// The scope associated with query and export operations.
/// This includes '/subscriptions/{subscriptionId}/' for subscription scope,
/// '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' for resourceGroup scope,
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for Billing Account scope and
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}' for Department scope,
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}' for EnrollmentAccount scope,
/// '/providers/Microsoft.Management/managementGroups/{managementGroupId} for Management Group scope,
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}' for billingProfile scope,
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}' for invoiceSection scope, and
/// '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}' specific for partners.
///
/// Note; not all are implemented
/// </summary>
public class Scope
{
    public static Scope Subscription(Guid subscriptionId) => new("Subscription", "/subscriptions/" + subscriptionId, true);
    public static Scope ResourceGroup(Guid subscriptionId, string resourceGroup) => new("ResourceGroup", $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}", true);
  
    private Scope(string name, string path, bool isSubscriptionBased)
    {
        Name = name;
        ScopePath = path;
        IsSubscriptionBased = isSubscriptionBased;
    }

    public string Name { get; init; }

    public string ScopePath
    {
        get;
        init;
    }

    public bool IsSubscriptionBased { get; set; }
}