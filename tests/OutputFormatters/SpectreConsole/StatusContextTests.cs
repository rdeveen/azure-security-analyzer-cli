using AzureSecurityAnalyzer.OutputFormatters.SpectreConsole;

using Shouldly;

namespace AzureSecurityAnalyzer.Tests.OutputFormatters.SpectreConsole;

public class StatusContextTests
{
    [Fact]
    public void SetStatus_InQuietMode_DoesNotThrow()
    {
        // Arrange - parameterless constructor is used in quiet mode
        var context = new StatusContext();

        // Act & Assert
        Should.NotThrow(() => context.Status = "Some status");
        context.Status.ShouldBeNull();
    }

    [Fact]
    public void Refresh_InQuietMode_DoesNotThrow()
    {
        // Arrange
        var context = new StatusContext();

        // Act & Assert
        Should.NotThrow(() => context.Refresh());
    }
}
