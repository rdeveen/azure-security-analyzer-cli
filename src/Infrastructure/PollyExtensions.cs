using System.Net;
using Polly;

namespace AzureSecurityAnalyzer.Infrastructure;

public class PollyExtensions
{
    public static IAsyncPolicy<HttpResponseMessage> GetRetryAfterPolicy()
    {
        return Policy.HandleResult<HttpResponseMessage>
                (msg => msg.StatusCode == HttpStatusCode.TooManyRequests)
            .WaitAndRetryAsync(
                retryCount: 5,
                sleepDurationProvider: (_, response, _) =>
                {
                    var retryAfterHeader = 
                        response.Result.Headers.FirstOrDefault(h => h.Key.Contains("retry-after", StringComparison.InvariantCultureIgnoreCase));
                    return retryAfterHeader.Key != null && int.TryParse(retryAfterHeader.Value.First(), out var seconds)
                        ? TimeSpan.FromSeconds(seconds)
                        : TimeSpan.FromSeconds(5);
                },
                onRetryAsync: (msg, time, retries, context) => Task.CompletedTask
            );
    }
}