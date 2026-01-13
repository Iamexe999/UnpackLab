namespace UnpackLab.Heuristics;

public static class EntropyAnalyzer
{
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;

        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;

        double entropy = 0;
        double len = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log(p, 2);
        }

        return entropy;
    }
}
