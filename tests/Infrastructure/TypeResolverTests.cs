using AwesomeAssertions;
using AzureSecurityAnalyzer.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace AzureSecurityAnalyzer.Tests.Infrastructure;

public class TypeResolverTests
{
    private interface IFoo
    {
    }

    private class Foo : IFoo
    {
    }

    [Fact]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Act
        var act = () => new TypeResolver(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Resolve_WithNullType_ReturnsNull()
    {
        // Arrange
        var services = new ServiceCollection();
        var resolver = new TypeResolver(services.BuildServiceProvider());

        // Act
        var result = resolver.Resolve(null!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Resolve_WithRegisteredType_ReturnsInstance()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton<IFoo, Foo>();
        var resolver = new TypeResolver(services.BuildServiceProvider());

        // Act
        var result = resolver.Resolve(typeof(IFoo));

        // Assert
        result.Should().BeOfType<Foo>();
    }

    [Fact]
    public void Dispose_DisposesUnderlyingProvider()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var resolver = new TypeResolver(provider);

        // Act
        var act = () => resolver.Dispose();

        // Assert
        act.Should().NotThrow();
    }
}
