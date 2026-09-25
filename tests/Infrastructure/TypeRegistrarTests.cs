using AwesomeAssertions;
using AzureSecurityAnalyzer.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Tests.Infrastructure;

public class TypeRegistrarTests
{
    private interface IFoo
    {
    }

    private class Foo : IFoo
    {
    }

    [Fact]
    public void Register_ResolvesRegisteredType()
    {
        // Arrange
        var services = new ServiceCollection();
        var registrar = new TypeRegistrar(services);
        registrar.Register(typeof(IFoo), typeof(Foo));

        // Act
        using var resolver = (IDisposable)registrar.Build();
        var resolved = ((ITypeResolver)resolver).Resolve(typeof(IFoo));

        // Assert
        resolved.Should().BeOfType<Foo>();
    }

    [Fact]
    public void RegisterInstance_ResolvesSameInstance()
    {
        // Arrange
        var services = new ServiceCollection();
        var registrar = new TypeRegistrar(services);
        var instance = new Foo();
        registrar.RegisterInstance(typeof(IFoo), instance);

        // Act
        using var resolver = (IDisposable)registrar.Build();
        var resolved = ((ITypeResolver)resolver).Resolve(typeof(IFoo));

        // Assert
        resolved.Should().BeSameAs(instance);
    }

    [Fact]
    public void RegisterLazy_InvokesFactoryWhenResolved()
    {
        // Arrange
        var services = new ServiceCollection();
        var registrar = new TypeRegistrar(services);
        var instance = new Foo();
        registrar.RegisterLazy(typeof(IFoo), () => instance);

        // Act
        using var resolver = (IDisposable)registrar.Build();
        var resolved = ((ITypeResolver)resolver).Resolve(typeof(IFoo));

        // Assert
        resolved.Should().BeSameAs(instance);
    }

    [Fact]
    public void RegisterLazy_WithNullFunc_ThrowsArgumentNullException()
    {
        // Arrange
        var services = new ServiceCollection();
        var registrar = new TypeRegistrar(services);

        // Act
        var act = () => registrar.RegisterLazy(typeof(IFoo), null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }
}
