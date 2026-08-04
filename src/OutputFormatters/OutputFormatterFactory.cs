using AzureSecurityAnalyzer.Commands;

namespace AzureSecurityAnalyzer.OutputFormatters;

public static class OutputFormatterFactory
{
    public static Dictionary<OutputFormat, BaseOutputFormatter> Create()
    {
        return new Dictionary<OutputFormat, BaseOutputFormatter>
        {
            { OutputFormat.Console, new ConsoleOutputFormatter() },
            { OutputFormat.Json, new JsonOutputFormatter() },
            { OutputFormat.Jsonc, new JsonOutputFormatter() },
            // { OutputFormat.Text, new TextOutputFormatter() },
            { OutputFormat.Markdown, new MarkdownOutputFormatter() },
            // { OutputFormat.Csv, new CsvOutputFormatter() }
        };
    }
}
