using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.RouteTables;

public class Analyzer
{
    private static readonly IReadOnlyCollection<IRouteTableAnomalyRule> Rules =
    [
        new MissingDefaultRouteToFirewallRule(),
        new InternetNextHopRule(),
        new NotAttachedToSubnetRule()
    ];

    public static Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(IReadOnlyCollection<RouteTable> routeTables)
    {
        var results = new List<AnomalyDetectionResult>();
        foreach (var routeTable in routeTables)
        {
            foreach (var rule in Rules)
            {
                var detection = rule.TryDetect(routeTable);
                if (detection is not null)
                {
                    results.Add(detection);
                }
            }
        }

        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private interface IRouteTableAnomalyRule
    {
        AnomalyDetectionResult? TryDetect(RouteTable routeTable);
    }

    private sealed class MissingDefaultRouteToFirewallRule : IRouteTableAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(RouteTable routeTable)
        {
            var routes = routeTable.Properties.Routes;
            if (routes is not { Length: > 0 } || !routes.Any(IsDefaultRouteToFirewall))
            {
                return new AnomalyDetectionResult(
                    routeTable,
                    "This route table has no default route to a firewall.",
                    SeverityLevel.Medium);
            }

            return null;
        }
    }

    private sealed class InternetNextHopRule : IRouteTableAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(RouteTable routeTable)
        {
            var route = routeTable.Properties.Routes?.FirstOrDefault(r =>
                IsDefaultRoute(r) &&
                MatchesValue(r.Properties.NextHopType, "Internet"));

            if (route is not null)
            {
                return new AnomalyDetectionResult(
                    routeTable,
                    $"This route table has a default route '{route.Name}' with the next hop set directly to the internet.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class NotAttachedToSubnetRule : IRouteTableAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(RouteTable routeTable)
        {
            if (routeTable.Properties.Subnets is not { Length: > 0 })
            {
                return new AnomalyDetectionResult(
                    routeTable,
                    "This route table is not attached to any subnets.",
                    SeverityLevel.Low);
            }

            return null;
        }
    }

    private static bool IsDefaultRouteToFirewall(Route route) =>
        IsDefaultRoute(route) &&
        MatchesValue(route.Properties.NextHopType, "VirtualAppliance") &&
        !string.IsNullOrWhiteSpace(route.Properties.NextHopIpAddress);

    private static bool IsDefaultRoute(Route route) =>
        MatchesValue(route.Properties.AddressPrefix, "0.0.0.0/0");

    private static bool MatchesValue(string? value, string? expectedValue) =>
        string.Equals(value, expectedValue, StringComparison.OrdinalIgnoreCase);
}

public record AnomalyDetectionResult(
    RouteTable RouteTable,
    string IssueDescription,
    SeverityLevel Severity);

public enum SeverityLevel
{
    Low,
    Medium,
    High
}
