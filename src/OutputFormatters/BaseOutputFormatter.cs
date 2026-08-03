using AzureSecurityAnalyzer.RegionsApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public abstract class BaseOutputFormatter
{
    public abstract Task WriteRegions(Commands.Regions.Settings settings, IReadOnlyCollection<AzureRegion> regions);
}
