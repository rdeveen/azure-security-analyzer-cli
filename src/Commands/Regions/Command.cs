using AzureSecurityAnalyzer.OutputFormatters;
using AzureSecurityAnalyzer.RegionsApi;
using Spectre.Console;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Commands.Regions;

public class Command(IRegionsRetriever regionsRetriever) : AsyncCommand<Regions.Settings>
{
    private readonly IRegionsRetriever regionsRetriever = regionsRetriever;
    private readonly Dictionary<OutputFormat, BaseOutputFormatter> outputFormatters = OutputFormatterFactory.Create();

    protected override async Task<int> ExecuteAsync(CommandContext context, Regions.Settings settings, CancellationToken cancellationToken)
    {
        CommandHelpers.PrintVersionIfDebug(settings.Debug);

        await AnsiConsoleExt.StatusAsync(settings.Quiet, "Fetching region data...", async ctx =>
        {

            var regions = await regionsRetriever.RetrieveRegions();

            // Write the output
            await outputFormatters[settings.Output]
                    .WriteRegions(settings, regions);
        });

        return 0;
    }
}