using System.Net;
using AwesomeAssertions;
using AzureSecurityAnalyzer.Infrastructure;

namespace AzureSecurityAnalyzer.Tests.Infrastructure;

public class PollyExtensionsTests
{
    [Fact]
    public async Task GetRetryAfterPolicy_WhenTooManyRequestsWithRetryAfterHeader_RetriesAndSucceeds()
    {
        // Arrange
        var policy = PollyExtensions.GetRetryAfterPolicy();
        var attempt = 0;

        // Act
        var result = await policy.ExecuteAsync(() =>
        {
            attempt++;
            if (attempt == 1)
            {
                var throttled = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                throttled.Headers.Add("Retry-After", "0");
                return Task.FromResult(throttled);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        // Assert
        result.StatusCode.Should().Be(HttpStatusCode.OK);
        attempt.Should().Be(2);
    }

    [Fact]
    public async Task GetRetryAfterPolicy_WhenNotThrottled_DoesNotRetry()
    {
        // Arrange
        var policy = PollyExtensions.GetRetryAfterPolicy();
        var attempt = 0;

        // Act
        var result = await policy.ExecuteAsync(() =>
        {
            attempt++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        // Assert
        result.StatusCode.Should().Be(HttpStatusCode.OK);
        attempt.Should().Be(1);
    }
}
