namespace UnpackLab.UnpackEngines;

public sealed record XorCandidate(
    string Variant,          // "xor-1byte", "xor-rolling-key"
    string KeyDescription,   // e.g. "0x5A" or "keylen=4"
    byte[] Output
);

public static class XorUnpacker
{
    public static IReadOnlyList<XorCandidate> TryCommonXors(byte[] input)
    {
        var results = new List<XorCandidate>();

        // 1) Single-byte XOR brute force (0x00..0xFF)
        for (int k = 0; k <= 0xFF; k++)
        {
            byte key = (byte)k;
            var outBuf = new byte[input.Length];

            for (int i = 0; i < input.Length; i++)
                outBuf[i] = (byte)(input[i] ^ key);

            results.Add(new XorCandidate("xor-1byte", $"0x{key:X2}", outBuf));
        }

        // 2) Rolling XOR keys of small lengths (heuristic keys, not brute force all combinations)
        // We'll try a handful of common human-picked keys and patterns.
        byte[][] commonKeys =
        [
            new byte[] { 0x10, 0x20, 0x30, 0x40 },
            new byte[] { 0x55, 0xAA },
            new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            new byte[] { (byte)'k', (byte)'e', (byte)'y' },
            new byte[] { (byte)'p', (byte)'a', (byte)'s', (byte)'s' }
        ];

        foreach (var key in commonKeys)
        {
            var outBuf = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                outBuf[i] = (byte)(input[i] ^ key[i % key.Length]);

            results.Add(new XorCandidate("xor-rolling-key", $"len={key.Length}", outBuf));
        }

        return results;
    }
}
