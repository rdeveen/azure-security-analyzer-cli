using AzureSecurityAnalyzer.OutputFormatters.SpectreConsole;

using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests.OutputFormatters.SpectreConsole;

public class StatusContextTests
{
    [Fact]
    public void SetStatus_InQuietMode_DoesNotThrow()
    {
        // Arrange - parameterless constructor is used in quiet mode
        var context = new StatusContext();

        // Act & Assert
        ((Action)(() => { context.Status = "Some status"; })).Should().NotThrow();
        context.Status.Should().BeNull();
    }

    [Fact]
    public void Refresh_InQuietMode_DoesNotThrow()
    {
        // Arrange
        var context = new StatusContext();

        // Act & Assert
        ((Action)(() => context.Refresh())).Should().NotThrow();
    }
}
