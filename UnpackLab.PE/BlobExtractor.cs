namespace UnpackLab.PE;

public sealed record BlobCandidate(
    string Source,          // e.g. ".text", "/19"
    int FileOffset,
    int Size
);

public static class BlobExtractor
{
    public static IReadOnlyList<BlobCandidate> FromSections(PeFile pe, int minSizeBytes = 4096)
    {
        var data = pe.AsSpan();
        var results = new List<BlobCandidate>();

        foreach (var s in pe.Sections)
        {
            if (s.SizeOfRawData == 0) continue;
            if (s.SizeOfRawData < (uint)minSizeBytes) continue;

            ulong end = (ulong)s.PointerToRawData + (ulong)s.SizeOfRawData;
            if (end > (ulong)data.Length) continue;

            results.Add(new BlobCandidate(
                Source: s.Name,
                FileOffset: (int)s.PointerToRawData,
                Size: (int)s.SizeOfRawData
            ));
        }

        return results;
    }
}
