using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Infrastructure;

public sealed class TypeResolver(IServiceProvider provider) : ITypeResolver, IDisposable
{
    private readonly IServiceProvider provider = provider ?? throw new ArgumentNullException(nameof(provider));
    public object? Resolve(Type? type) => type is null ? null : provider.GetService(type);
    public void Dispose() => (provider as IDisposable)?.Dispose();
}