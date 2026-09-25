using AzureSecurityAnalyzer.OutputFormatters.SpectreConsole;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Spectre.Console;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static partial class AnsiConsoleExt
{
    /// <summary>
    /// Creates a new <see cref="StatusExt"/> instance.
    /// </summary>
    /// <returns>A <see cref="StatusExt"/> instance.</returns>
    public static StatusExt Status()
    {
        return new StatusExt(AnsiConsole.Console);
    }

    /// <summary>
    /// Runs <paramref name="action"/> either wrapped in a status spinner (when
    /// <paramref name="quiet"/> is <c>false</c>) or directly without any
    /// status/progress output (when <paramref name="quiet"/> is <c>true</c>).
    /// </summary>
    public static async Task StatusAsync(bool quiet, string statusText, Func<AzureSecurityAnalyzer.OutputFormatters.SpectreConsole.StatusContext, Task> action)
    {
        if (quiet)
        {
            await action(new AzureSecurityAnalyzer.OutputFormatters.SpectreConsole.StatusContext()).ConfigureAwait(false);
        }
        else
        {
            await Status().StartAsync(statusText, action).ConfigureAwait(false);
        }
    }
}