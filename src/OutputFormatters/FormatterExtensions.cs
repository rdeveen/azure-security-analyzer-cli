using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public static class FormatterExtensions
{
    extension(SecurityRuleProperties properties)
    {
        public string GetValue(string? singularValue, string[]? pluralValues)
        {
            return !string.IsNullOrEmpty(singularValue)
                ? singularValue
                : string.Join(",", pluralValues ?? []);
        }
    }

    extension(NetworkSecurityGroup networkSecurityGroup)
    {
        public string GetResourceGroupName()
        {
            return GetSegmentValue(networkSecurityGroup.Id, "resourceGroups");
        }

        public string[] GetAttachedNames()
        {
            var subnets = networkSecurityGroup.Properties.Subnets ?? [];
            var networkInterfaces = networkSecurityGroup.Properties.NetworkInterfaces ?? [];

            return GetNames(subnets, "subnets", "Subnet")
                .Concat(GetNames(networkInterfaces, "networkInterfaces", "NIC"))
                .ToArray();
        }
    }

    private static IEnumerable<string> GetNames(ResourceReference[] references, string segmentName, string label)
    {
        return references
            .Select(r => GetSegmentValue(r.Id, segmentName))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .Select(s => $"{label}: {s}");
    }

    private static string GetSegmentValue(string resourceId, string segmentName)
    {
        var segments = resourceId.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var index = Array.FindIndex(segments, s => string.Equals(s, segmentName, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < segments.Length ? segments[index + 1] : string.Empty;
    }
}