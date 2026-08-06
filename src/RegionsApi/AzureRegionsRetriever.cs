using System.Net.Http.Json;

namespace AzureSecurityAnalyzer.RegionsApi;

public interface IRegionsRetriever
{
    Task<IReadOnlyCollection<AzureRegion>> RetrieveRegions();
}

public class AzureRegionsRetriever(IHttpClientFactory httpClientFactory) : IRegionsRetriever
{
    private readonly HttpClient client = httpClientFactory.CreateClient("RegionsApi");

    public async Task<IReadOnlyCollection<AzureRegion>> RetrieveRegions()
    {
        var uri = new Uri(
            $"globe/data/geo/regions.json",
            UriKind.Relative);

        var response = await client.GetAsync(uri);

        response.EnsureSuccessStatusCode();

        var regions = await response.Content.ReadFromJsonAsync<IReadOnlyCollection<AzureRegion>>(
            new System.Text.Json.JsonSerializerOptions()
        {
            PropertyNameCaseInsensitive = true,
        }) ?? [];

        return regions;
    }
}

public record AzureRegion(
    string Id,
    string Continent,
    string GeographyId,
    string DisplayName,
    string Location,
    double Latitude,
    double Longitude,
    string TypeId,
    bool IsOpen,
    int? YearOpen,
    string[] ComplianceIds,
    bool HasGroundStation,
    string DataResidency,
    string AvailableTo,
    string AvailabilityZonesId,
    string[] AvailabilityZonesNearestRegionIds,
    string ProductsByRegionLink,
    string ProductsByRegionLinkNonRegional,
    string[] SustainabilityIds,
    string[] DisasterRecoveryCrossRegionIds,
    string[] DisasterRecoveryInRegionIds)
{
}