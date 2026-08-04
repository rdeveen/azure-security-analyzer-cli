using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public static class SecurityRulePropertiesExtensions
{
    public static string GetValue(this SecurityRuleProperties properties, string? singularValue, string[]? pluralValues)
    {
        return !string.IsNullOrEmpty(singularValue)
            ? singularValue
            : string.Join(",", pluralValues ?? []);
    }
}