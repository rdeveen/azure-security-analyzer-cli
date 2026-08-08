using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;

public class Analyzer(Settings settings)
{
    public Settings Settings { get; } = settings;

    public static async Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        var results = new List<AnomalyDetectionResult>();
        foreach (var nsg in networkSecurityGroups)
        {
            // Check for NSGs with no security rules
            if (nsg.Properties.SecurityRules == null || nsg.Properties.SecurityRules.Length == 0)
            {
                results.Add(new AnomalyDetectionResult(
                    nsg,
                    "This Network Security Group has no security rules defined.",
                    SeverityLevel.Medium));
            }

            // Check for NSGs with security rules that allow all inbound and outbound traffic
            if (nsg.Properties.SecurityRules != null && nsg.Properties.SecurityRules.Any(r =>
                string.Equals(r.Properties.Access, "Allow", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(r.Properties.Direction, "Inbound", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(r.Properties.SourceAddressPrefix, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.SourceAddressPrefixes != null && r.Properties.SourceAddressPrefixes.Contains("*"))) &&
                (string.Equals(r.Properties.DestinationAddressPrefix, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.DestinationAddressPrefixes != null && r.Properties.DestinationAddressPrefixes.Contains("*"))) &&
                (string.Equals(r.Properties.SourcePortRange, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.SourcePortRanges != null && r.Properties.SourcePortRanges.Contains("*"))) &&
                (string.Equals(r.Properties.DestinationPortRange, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.DestinationPortRanges != null && r.Properties.DestinationPortRanges.Contains("*")))))
            {
                results.Add(new AnomalyDetectionResult(
                    nsg,
                    "This Network Security Group has security rules that allow all inbound and outbound traffic.",
                    SeverityLevel.High));
            }

            // Check for NSGs with security rules that allow inbound traffic from the internet on common ports (e.g., 22, 3389)
            if (nsg.Properties.SecurityRules != null && nsg.Properties.SecurityRules.Any(r =>
                string.Equals(r.Properties.Access, "Allow", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(r.Properties.Direction, "Inbound", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(r.Properties.SourceAddressPrefix, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.SourceAddressPrefixes != null && r.Properties.SourceAddressPrefixes.Contains("*"))) &&
                (string.Equals(r.Properties.DestinationPortRange, "22", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.DestinationPortRanges != null && r.Properties.DestinationPortRanges.Contains("22")) ||
                 string.Equals(r.Properties.DestinationPortRange, "3389", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.DestinationPortRanges != null && r.Properties.DestinationPortRanges.Contains("3389")))))
            {
                results.Add(new AnomalyDetectionResult(
                    nsg,
                    "This Network Security Group has security rules that allow inbound traffic from the internet on common ports (e.g., 22, 3389).",
                    SeverityLevel.High));
            }

            // Check for NSGs with security rules that allow inbound traffic from the internet on all ports
            if (nsg.Properties.SecurityRules != null && nsg.Properties.SecurityRules.Any(r =>
                string.Equals(r.Properties.Access, "Allow", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(r.Properties.Direction, "Inbound", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(r.Properties.SourceAddressPrefix, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.SourceAddressPrefixes != null && r.Properties.SourceAddressPrefixes.Contains("*"))) &&
                (string.Equals(r.Properties.DestinationPortRange, "*", StringComparison.OrdinalIgnoreCase) ||
                 (r.Properties.DestinationPortRanges != null && r.Properties.DestinationPortRanges.Contains("*")))))
            {
                results.Add(new AnomalyDetectionResult(
                    nsg,
                    "This Network Security Group has security rules that allow inbound traffic from the internet on all ports.",
                    SeverityLevel.High));
            }

            // Check for NSGs not attached to any subnets or network interfaces
            if (nsg.Properties.Subnets == null || nsg.Properties.Subnets.Length == 0)
            {
                results.Add(new AnomalyDetectionResult(
                    nsg,
                    "This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.",
                    SeverityLevel.Low));
            }
        }
        return results;
    }
}

public record AnomalyDetectionResult(
    NetworkSecurityGroup NetworkSecurityGroup, 
    string IssueDescription, 
    SeverityLevel Severity);

public enum SeverityLevel
{
    Low,
    Medium,
    High
}