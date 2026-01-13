using System;

namespace UnpackLab.UnpackEngines;

public static class DemoSamples
{
    /// <summary>
    /// Creates an XOR-obfuscated blob that will look like it contains an embedded PE header
    /// after XORing with the returned key.
    ///
    /// This is intentionally a *toy* structure: "MZ" + e_lfanew + "PE\0\0".
    /// It is not a runnable executable and is safe for testing triage logic.
    /// </summary>
    public static (byte[] ObfuscatedBlob, byte XorKey) CreateXorEmbeddedPeToyBlob(
        int size = 512,
        byte key = 0x5A,
        int peHeaderOffset = 0x80)
    {
        if (size < 0x100) size = 0x100;
        if (peHeaderOffset < 0x80) peHeaderOffset = 0x80;
        if (peHeaderOffset + 4 >= size) size = peHeaderOffset + 8;

        // Plain (deobfuscated) buffer: add minimal PE-like markers
        var plain = new byte[size];

        // Fill with deterministic pseudo-random bytes (so entropy isn't zero, but reproducible)
        var rng = new Random(1337);
        rng.NextBytes(plain);

        // "MZ"
        plain[0] = (byte)'M';
        plain[1] = (byte)'Z';

        // e_lfanew at 0x3C -> points to PE signature within buffer
        // (little-endian 32-bit)
        int e_lfanew = peHeaderOffset;
        plain[0x3C] = (byte)(e_lfanew & 0xFF);
        plain[0x3D] = (byte)((e_lfanew >> 8) & 0xFF);
        plain[0x3E] = (byte)((e_lfanew >> 16) & 0xFF);
        plain[0x3F] = (byte)((e_lfanew >> 24) & 0xFF);

        // "PE\0\0" at e_lfanew
        plain[peHeaderOffset + 0] = (byte)'P';
        plain[peHeaderOffset + 1] = (byte)'E';
        plain[peHeaderOffset + 2] = 0;
        plain[peHeaderOffset + 3] = 0;

        // Obfuscate via XOR key
        var obf = new byte[plain.Length];
        for (int i = 0; i < plain.Length; i++)
            obf[i] = (byte)(plain[i] ^ key);

        return (obf, key);
    }
}
