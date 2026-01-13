using System.IO.Compression;

namespace UnpackLab.UnpackEngines;

public sealed record DecompressionResult(
    string Variant,      // "zlib" or "raw-deflate"
    int InputSize,
    int OutputSize,
    string OutputFile
);

public static class DeflateDecompressor
{
    public static IReadOnlyList<byte[]> TryDecompressAll(byte[] input, int maxOutputBytes = 50 * 1024 * 1024)
    {
        var outputs = new List<byte[]>();

        // Variant A: zlib-wrapped deflate (skip 2-byte header)
        // zlib header is 2 bytes: CMF/FLG. Many streams start with 0x78 0x9C/0xDA/0x01...
        if (input.Length > 2 && LooksLikeZlibHeader(input))
        {
            var z = TryInflateZlib(input, maxOutputBytes);
            if (z is not null) outputs.Add(z);
        }

        // Variant B: raw deflate (no wrapper)
        var raw = TryInflateRawDeflate(input, maxOutputBytes);
        if (raw is not null) outputs.Add(raw);

        return outputs;
    }

    public static bool LooksLikeZlibHeader(byte[] input)
    {
        // RFC1950: CMF*256 + FLG must be divisible by 31
        if (input.Length < 2) return false;
        int cmf = input[0];
        int flg = input[1];
        int v = (cmf << 8) | flg;
        if (v % 31 != 0) return false;

        int cm = cmf & 0x0F;
        // 8 = deflate
        return cm == 8;
    }

    private static byte[]? TryInflateZlib(byte[] input, int maxOutputBytes)
    {
        try
        {
            // Skip the 2-byte zlib header, ignore Adler32 at end (DeflateStream stops before it)
            using var msIn = new MemoryStream(input, 2, input.Length - 2);
            using var ds = new DeflateStream(msIn, CompressionMode.Decompress, leaveOpen: true);
            return ReadAllWithLimit(ds, maxOutputBytes);
        }
        catch
        {
            return null;
        }
    }

    private static byte[]? TryInflateRawDeflate(byte[] input, int maxOutputBytes)
    {
        try
        {
            using var msIn = new MemoryStream(input);
            using var ds = new DeflateStream(msIn, CompressionMode.Decompress, leaveOpen: true);
            return ReadAllWithLimit(ds, maxOutputBytes);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] ReadAllWithLimit(Stream s, int maxBytes)
    {
        using var msOut = new MemoryStream();
        var buf = new byte[8192];

        while (true)
        {
            int n = s.Read(buf, 0, buf.Length);
            if (n <= 0) break;

            msOut.Write(buf, 0, n);

            if (msOut.Length > maxBytes)
                throw new InvalidDataException($"Decompressed output exceeded limit ({maxBytes} bytes).");
        }

        return msOut.ToArray();
    }
}
