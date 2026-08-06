using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace AzureSecurityAnalyzer.Infrastructure;

public static class AzCommand
{
    public static string GetDefaultAzureSubscriptionId()
    {
        var filename = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "cmd.exe" : "az";
        var arguments = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "/d /c az account show" : "account show";
        
        var startInfo = new ProcessStartInfo
        {
            FileName = filename,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };

        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            string error = process.StandardError.ReadToEnd();
            throw new Exception($"Error executing 'az account show': {error}");
        }

        using var jsonDocument = JsonDocument.Parse(output);

        JsonElement root = jsonDocument.RootElement;
        if (root.TryGetProperty("id", out JsonElement idElement))
        {
            string subscriptionId = idElement.GetString() ?? throw new Exception("The 'id' property is null.");
            return subscriptionId;
        }
        else
        {
            throw new Exception("Unable to find the 'id' property in the JSON output.");
        }
    }
}