using System.Text.Json;
using System.Text.Json.Serialization;
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

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups, IReadOnlyCollection<Commands.NetworkSecurityGroups.AnomalyDetectionResult> analysisResults)
    {
        // Write the network security groups and their analysis results as JSON
        // The analysis results are included in the output for each network security group
        // Group the analysis results by network security group and include them in the output
        // Remove the nsg from the analysis results to avoid duplication
        
        var output = networkSecurityGroups.Select(nsg =>
        {
            var nsgAnalysisResults = analysisResults.Where(r => r.NetworkSecurityGroup.Id == nsg.Id).ToList();

            return new
            {
                NetworkSecurityGroup = nsg,
                Anomalies = nsgAnalysisResults.Select(r => new
                {
                    r.IssueDescription,
                    r.Severity
                }).ToList()
            };
        }).ToList();

        WriteJson(settings, output);

        return Task.CompletedTask;
    }

    public override Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations)
    {
        WriteJson(settings, recommendations);

        return Task.CompletedTask;
    }

    public override Task WriteRouteTables(Commands.RouteTables.Settings settings, IReadOnlyCollection<RouteTable> routeTables, IReadOnlyCollection<Commands.RouteTables.AnomalyDetectionResult> analysisResults)
    {
        var output = routeTables.Select(routeTable =>
        {
            var routeTableAnalysisResults = analysisResults.Where(r => r.RouteTable.Id == routeTable.Id).ToList();

            return new
            {
                RouteTable = routeTable,
                Anomalies = routeTableAnalysisResults.Select(r => new
                {
                    r.IssueDescription,
                    r.Severity
                }).ToList()
            };
        }).ToList();

        WriteJson(settings, output);

        return Task.CompletedTask;
    }

    private static void WriteJson(Commands.ICommandSettings settings, object items)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        options.Converters.Add(new JsonStringEnumConverter());

        var json = JsonSerializer.Serialize(items, options);

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