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

    extension(RouteTable routeTable)
    {
        public string GetResourceGroupName()
        {
            return GetSegmentValue(routeTable.Id, "resourceGroups");
        }

        public string[] GetAttachedSubnetNames()
        {
            var subnets = routeTable.Properties.Subnets ?? [];
            return GetNames(subnets, "subnets", "Subnet").ToArray();
        }
    }

    extension(AdvisorRecommendation recommendation)
    {
        public int GetImpactOrder()
        {
            return recommendation.Properties.Impact switch
            {
                "High" => 0,
                "Medium" => 1,
                "Low" => 2,
                _ => 3
            };
        }
    }

    extension(AzureResourceDetails resourceDetails)
    {
        public string GetResourceType()
        {
            return GetSegmentValue(resourceDetails.Id, "providers");
        }

        public string GetResourceName()
        {
            return GetSegmentValue(resourceDetails.Id, GetSegmentValue(resourceDetails.Id, "providers"));
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