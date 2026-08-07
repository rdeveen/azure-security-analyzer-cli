using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.RegionsApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public abstract class BaseOutputFormatter
{
    public abstract Task WriteRegions(Commands.Regions.Settings settings, IReadOnlyCollection<AzureRegion> regions);

    public abstract Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups);

    public abstract Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations);
}
