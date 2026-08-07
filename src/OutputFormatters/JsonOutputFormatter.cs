using System.Text.Json;
using AzureSecurityAnalyzer.Commands;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.RegionsApi;
using Spectre.Console;
using Spectre.Console.Json;

namespace AzureSecurityAnalyzer.OutputFormatters;

public class JsonOutputFormatter : BaseOutputFormatter
{
    public override Task WriteRegions(Commands.Regions.Settings settings, IReadOnlyCollection<AzureRegion> regions)
    {
        WriteJson(settings, regions);

        return Task.CompletedTask;
    }
    
    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        WriteJson(settings, networkSecurityGroups);

        return Task.CompletedTask;
    }

    public override Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations)
    {
        WriteJson(settings, recommendations);

        return Task.CompletedTask;
    }

    private static void WriteJson(Commands.ICostSettings settings, object items)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        
        var json = JsonSerializer.Serialize(items, options );

        switch (settings.Output)
        {
            case OutputFormat.Json:
                Console.Write(json);
                break;
            case OutputFormat.Jsonc:
                AnsiConsole.Write(
                    new JsonText(json)
                        .BracesColor(Color.Red)
                        .BracketColor(Color.Green)
                        .ColonColor(Color.Blue)
                        .CommaColor(Color.Gray)
                        .StringColor(Color.Green)
                        .NumberColor(Color.Blue)
                        .BooleanColor(Color.Red)
                        .NullColor(Color.Green));
                break;
            default:
                throw new ArgumentException($"JsonOutputFormatter does not support output format: {settings.Output}");
        }
    }
}