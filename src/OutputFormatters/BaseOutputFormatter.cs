using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.RegionsApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public abstract class BaseOutputFormatter
{
    public abstract Task WriteRegions(Commands.Regions.Settings settings, IReadOnlyCollection<AzureRegion> regions);

    public abstract Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups, IReadOnlyCollection<Commands.NetworkSecurityGroups.AnomalyDetectionResult> analysisResults);

    public abstract Task WriteRouteTables(Commands.RouteTables.Settings settings, IReadOnlyCollection<RouteTable> routeTables, IReadOnlyCollection<Commands.RouteTables.AnomalyDetectionResult> analysisResults);

    public abstract Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations);
}
