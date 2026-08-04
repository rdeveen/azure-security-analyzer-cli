using System.Text.Json;
using AzureSecurityAnalyzer.Commands;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.RegionsApi;
using DevLab.JmesPath;
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

    private static void WriteJson(Commands.ICostSettings settings, object items)
    {

        var options = new JsonSerializerOptions { WriteIndented = true };
        
        var json = JsonSerializer.Serialize(items, options );

        if (!string.IsNullOrWhiteSpace(settings.Query))
        {
            var jmes = new JmesPath();

            json = jmes.Transform(json, settings.Query);
        }

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
                        .CommaColor(Color.Red)
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