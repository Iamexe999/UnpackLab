using UnpackLab.PE;

namespace UnpackLab.Heuristics;

public sealed record PackerHeuristicResult(
    int Score,
    bool LikelyPacked,
    IReadOnlyList<string> Reasons
);

public static class PackerHeuristics
{
    private const double HighEntropy = 7.20;
    private const double MediumEntropy = 6.60;

    private static readonly string[] SuspiciousNames =
    {
        "upx", "aspack", "mpress", "petite", "fsg", "themida", "vmprotect", "packed"
    };

    // Common “dynamic resolve” APIs that show up in packed samples (when they import at all)
    private static readonly string[] SuspiciousApis =
    {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"
    };

    public static PackerHeuristicResult Evaluate(
        PeFile pe,
        IReadOnlyDictionary<string, double> entropyBySection,
        ImportTable? imports = null)
    {
        var reasons = new List<string>();
        int score = 0;

        // 1) High entropy sections
        var highEnt = entropyBySection
            .Where(kv => kv.Value >= HighEntropy)
            .OrderByDescending(kv => kv.Value)
            .ToList();

        if (highEnt.Count > 0)
        {
            score += 50;
            reasons.Add($"High entropy section(s): {string.Join(", ", highEnt.Select(h => $"{h.Key}={h.Value:F3}"))}");
        }

        // 2) Medium-high entropy sections
        var medEnt = entropyBySection
            .Where(kv => kv.Value >= MediumEntropy && kv.Value < HighEntropy)
            .OrderByDescending(kv => kv.Value)
            .ToList();

        if (medEnt.Count > 0)
        {
            score += Math.Min(20, medEnt.Count * 5);
            reasons.Add($"Medium-high entropy section(s): {string.Join(", ", medEnt.Select(h => $"{h.Key}={h.Value:F3}"))}");
        }

        // 3) Suspicious section names
        foreach (var s in pe.Sections)
        {
            var name = s.Name.ToLowerInvariant();
            if (SuspiciousNames.Any(sig => name.Contains(sig)))
            {
                score += 30;
                reasons.Add($"Suspicious section name: {s.Name}");
                break;
            }
        }

        // 4) One dominant section (common in packers: a big blob)
        ulong totalRaw = 0;
        foreach (var s in pe.Sections) totalRaw += s.SizeOfRawData;

        if (totalRaw > 0)
        {
            var largest = pe.Sections.OrderByDescending(s => s.SizeOfRawData).First();
            double frac = (double)largest.SizeOfRawData / totalRaw;

            if (frac >= 0.75)
            {
                score += 25;
                reasons.Add($"Single dominant section: {largest.Name} is {(frac * 100):F1}% of raw bytes");
            }
        }

        // 5) Import sparsity (strong real-world signal)
        if (imports is not null)
        {
            int modCount = imports.ModuleCount;
            int fnCount = imports.FunctionCount;

            // Many packed samples import very little (or only resolve dynamically).
            if (fnCount == 0 && modCount == 0)
            {
                score += 35;
                reasons.Add("No imports found (possible packed/dynamically-resolved imports).");
            }
            else
            {
                if (fnCount <= 8)
                {
                    score += 35;
                    reasons.Add($"Very low import count: {fnCount} functions across {modCount} module(s).");
                }
                else if (fnCount <= 20)
                {
                    score += 20;
                    reasons.Add($"Low import count: {fnCount} functions across {modCount} module(s).");
                }

                if (modCount <= 1 && fnCount > 0)
                {
                    score += 10;
                    reasons.Add($"Imports concentrated in {modCount} module(s).");
                }

                // Heuristic: if the only “interesting” imports are dynamic loaders, that’s suspicious.
                // (This is a weak/medium signal; many legit programs also call these.)
                bool hasSuspiciousApi = imports.Modules
                    .SelectMany(m => m.Functions)
                    .Any(f => SuspiciousApis.Contains(f, StringComparer.OrdinalIgnoreCase));

                if (hasSuspiciousApi && fnCount <= 20)
                {
                    score += 10;
                    reasons.Add("Dynamic loader APIs present with low overall imports (possible runtime import resolution).");
                }
            }
        }

        score = Math.Clamp(score, 0, 100);
        bool likelyPacked = score >= 60;

        if (reasons.Count == 0)
            reasons.Add("No strong packing indicators from entropy/section layout/imports.");

        return new(score, likelyPacked, reasons);
    }
}
