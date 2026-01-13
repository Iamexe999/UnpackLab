using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;

public class DemoPipelineTests
{
    [Fact]
    public void Triage_Finds_EmbeddedPe_In_DemoBlob()
    {
        var repoRoot = FindRepoRoot();
        var demoDir = Path.Combine(repoRoot, "demo_blobs_test");
        var triageOut = Path.Combine(repoRoot, "out_triage_test");

        if (Directory.Exists(demoDir)) Directory.Delete(demoDir, recursive: true);
        if (Directory.Exists(triageOut)) Directory.Delete(triageOut, recursive: true);

        Directory.CreateDirectory(demoDir);
        Directory.CreateDirectory(triageOut);

        // 1) Generate demo blobs
        RunDotnet(repoRoot, $"run --project UnpackLab.Cli -- make-demo --out \"{demoDir}\"");

        // 2) Triage them
        RunDotnet(repoRoot, $"run --project UnpackLab.Cli -- triage \"{demoDir}\" --out \"{triageOut}\" --top 10 --min-score 10");

        // 3) Validate manifest contains PE hit(s)
        var manifestPath = Path.Combine(triageOut, "triage_manifest.json");
        Assert.True(File.Exists(manifestPath), "triage_manifest.json not found");

        using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var anyPeHits = doc.RootElement.EnumerateArray()
            .Any(e => e.TryGetProperty("PeHits", out var p) && p.GetInt32() > 0);

        Assert.True(anyPeHits, "Expected at least one triage result with PeHits > 0");
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "UnpackLab.Cli")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not find repo root (directory containing UnpackLab.Cli).");
    }

    private static void RunDotnet(string workingDir, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = args,
            WorkingDirectory = workingDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var p = Process.Start(psi)!;
        if (!p.WaitForExit(120_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"dotnet {args} timed out");
        }

        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();

        if (p.ExitCode != 0)
        {
            throw new Exception(
                $"dotnet {args} failed with exit code {p.ExitCode}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}");
        }
    }
}
