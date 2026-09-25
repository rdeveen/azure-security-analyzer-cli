using System.Diagnostics;
using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests;

public class ProgramTests
{
    [Fact]
    public async Task RunningHelp_ShowsHelpForAvailableCommands()
    {
        var projectPath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "src", "azure-security-analyzer-cli.csproj"));

        var startInfo = new ProcessStartInfo("dotnet", $"run --project \"{projectPath}\" -- --help")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var process = Process.Start(startInfo);
        process.Should().NotBeNull();

        var standardOutputTask = process!.StandardOutput.ReadToEndAsync();
        var standardErrorTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync(CancellationToken.None);

        var standardOutput = await standardOutputTask;
        var standardError = await standardErrorTask;

        process.ExitCode.Should().Be(0);
        standardError.Should().BeEmpty();
        standardOutput.Should().Contain("USAGE:");
        standardOutput.Should().Contain("azure-security-analyzer");
        standardOutput.Should().Contain("<COMMAND>");
        standardOutput.Should().Contain("COMMANDS:");
        standardOutput.Should().Contain("nsg");
        standardOutput.Should().Contain("firewall");
        standardOutput.Should().Contain("route-tables");
        standardOutput.Should().Contain("advisor");
    }
}
