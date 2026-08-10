using AzureSecurityAnalyzer.Commands;
using AwesomeAssertions;
using Spectre.Console;

namespace AzureSecurityAnalyzer.Tests.Commands;

public class CommandHelpersTests
{
    [Fact]
    public void ValidateAndResolveSubscription_WithSubscription_ReturnsSuccess()
    {
        // Arrange
        var subscription = (Guid?)Guid.NewGuid();
        Guid captured = Guid.Empty;

        // Act
        var result = CommandHelpers.ValidateAndResolveSubscription(
            subscription, isSubscriptionBased: true, id => captured = id);

        // Assert
        result.Successful.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndResolveSubscription_NotSubscriptionBased_ReturnsSuccess()
    {
        // Arrange & Act
        var result = CommandHelpers.ValidateAndResolveSubscription(
            subscription: null, isSubscriptionBased: false, _ => { });

        // Assert
        result.Successful.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndResolveSubscription_NoSubscriptionAndSubscriptionBased_AttemptsAzCliResolution()
    {
        // Arrange
        Guid captured = Guid.Empty;

        // Act - when az CLI is available it succeeds and calls setSubscription;
        // when az CLI is not available it returns an error.
        var result = CommandHelpers.ValidateAndResolveSubscription(
            subscription: null, isSubscriptionBased: true, id => captured = id);

        // Assert - either it resolved successfully (az CLI present) or returned an error
        if (result.Successful)
        {
            captured.Should().NotBe(Guid.Empty);
        }
        else
        {
            captured.Should().Be(Guid.Empty);
        }
    }

    [Fact]
    public void PrintVersionIfDebug_WithDebugTrue_DoesNotThrow()
    {
        // Act & Assert - should not throw
        ((Action)(() => CommandHelpers.PrintVersionIfDebug(true))).Should().NotThrow();
    }

    [Fact]
    public void PrintVersionIfDebug_WithDebugFalse_DoesNotThrow()
    {
        // Act & Assert - should not throw
        ((Action)(() => CommandHelpers.PrintVersionIfDebug(false))).Should().NotThrow();
    }
}