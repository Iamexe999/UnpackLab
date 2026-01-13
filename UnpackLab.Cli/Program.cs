using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using UnpackLab.PE;
using UnpackLab.Heuristics;
using UnpackLab.UnpackEngines;

static int PrintUsage()
{
    Console.WriteLine("UnpackLab - defensive unpacking lab tool");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  unpacklab analyze <path-to-pe>");
    Console.WriteLine("  unpacklab extract <path-to-pe> --out <output-dir> [--min-entropy 6.6] [--min-size 4096] [--all]");
    Console.WriteLine("  unpacklab decompress <path-to-blob-or-dir> --out <output-dir> [--max-out 52428800]");
    Console.WriteLine("  unpacklab xor <path-to-blob-or-dir> --out <output-dir> [--min-entropy-drop 0.7] [--require-mz] [--top 10] [--full]");
    Console.WriteLine("  unpacklab triage <blob-dir> --out <output-dir> [--top 15] [--min-score 10] [--max-out 52428800] [--full-xor]");
    Console.WriteLine("  unpacklab make-demo --out <output-dir>");
    Console.WriteLine();
    Console.WriteLine("Notes:");
    Console.WriteLine("  - For decompress/xor: if input is a directory, all *.bin files are tried.");
    Console.WriteLine("  - triage runs deflate + xor and ranks candidates.");
    Console.WriteLine("  - make-demo generates safe toy blobs for deterministic demos/tests.");
    Console.WriteLine();
    return 2;
}

static string? GetArgValue(string[] a, string name)
{
    for (int i = 0; i < a.Length - 1; i++)
        if (string.Equals(a[i], name, StringComparison.OrdinalIgnoreCase))
            return a[i + 1];
    return null;
}

static bool HasArg(string[] a, string name)
    => a.Any(x => string.Equals(x, name, StringComparison.OrdinalIgnoreCase));

static double ParseDoubleOr(string? s, double fallback)
    => double.TryParse(s, out var v) ? v : fallback;

static int ParseIntOr(string? s, int fallback)
    => int.TryParse(s, out var v) ? v : fallback;

if (args.Length < 1)
    return PrintUsage();

var cmd = args[0];

try
{
    if (string.Equals(cmd, "make-demo", StringComparison.OrdinalIgnoreCase))
        return CmdMakeDemo(args);

    if (args.Length < 2)
        return PrintUsage();

    var targetPath = args[1];

    if (string.Equals(cmd, "analyze", StringComparison.OrdinalIgnoreCase))
        return CmdAnalyze(targetPath);

    if (string.Equals(cmd, "extract", StringComparison.OrdinalIgnoreCase))
        return CmdExtract(args, targetPath);

    if (string.Equals(cmd, "decompress", StringComparison.OrdinalIgnoreCase))
        return CmdDecompress(args, targetPath);

    if (string.Equals(cmd, "xor", StringComparison.OrdinalIgnoreCase))
        return CmdXor(args, targetPath);

    if (string.Equals(cmd, "triage", StringComparison.OrdinalIgnoreCase))
        return CmdTriage(args, targetPath);

    return PrintUsage();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

// ---------------- Commands ----------------

static int CmdMakeDemo(string[] args)
{
    var outDir = GetArgValue(args, "--out");
    if (string.IsNullOrWhiteSpace(outDir))
    {
        Console.Error.WriteLine("Missing required option: --out <output-dir>");
        return 2;
    }

    Directory.CreateDirectory(outDir);

    // Demo 1: XOR-obfuscated toy embedded PE markers (MZ + PE\0\0)
    var (obf, key) = DemoSamples.CreateXorEmbeddedPeToyBlob(size: 512, key: 0x5A, peHeaderOffset: 0x80);
    var blobName = $"demo_xor_embedded_pe_key0x{key:X2}.bin";
    File.WriteAllBytes(Path.Combine(outDir, blobName), obf);

    // Optional: a small plain blob for contrast (non-hit)
    var plainNoise = new byte[512];
    new Random(123).NextBytes(plainNoise);
    File.WriteAllBytes(Path.Combine(outDir, "demo_noise.bin"), plainNoise);

    // Demo manifest
    var manifest = new
    {
        createdUtc = DateTime.UtcNow.ToString("O"),
        blobs = new object[]
        {
            new {
                file = blobName,
                description = "XOR-obfuscated toy buffer. After XOR with key, it contains MZ + e_lfanew + PE\\0\\0.",
                expected = new {
                    engine = "xor",
                    variant = $"xor-1byte:{key:X2}",
                    embeddedPeOffset = 0
                }
            },
            new {
                file = "demo_noise.bin",
                description = "Random noise blob for contrast. Should not produce PE hits."
            }
        }
    };

    var manifestPath = Path.Combine(outDir, "demo_manifest.json");
    File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

    Console.WriteLine($"Demo blobs written to: {Path.GetFullPath(outDir)}");
    Console.WriteLine($"  - {blobName}");
    Console.WriteLine($"  - demo_noise.bin");
    Console.WriteLine($"Manifest: {manifestPath}");
    Console.WriteLine();
    Console.WriteLine("Next:");
    Console.WriteLine($"  dotnet run --project UnpackLab.Cli -- triage \"{outDir}\" --out out\\triage_demo --top 10 --min-score 10");

    return 0;
}

static int CmdAnalyze(string path)
{
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"File not found: {path}");
        return 2;
    }

    var pe = PeFile.Load(path);
    var bytes = pe.AsSpan();

    Console.WriteLine($"File: {Path.GetFullPath(path)}");
    Console.WriteLine($"Arch: {(pe.Is64Bit ? "x64 (PE32+)" : "x86 (PE32)")}");
    Console.WriteLine($"EntryPoint RVA: 0x{pe.AddressOfEntryPoint:X8}");
    Console.WriteLine();

    Console.WriteLine("Sections:");
    Console.WriteLine("  Name       RawSize    RawPtr     Entropy");
    Console.WriteLine("  --------   --------   --------   --------");

    var entropyBySection = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);

    foreach (var s in pe.Sections)
    {
        double ent = 0;

        var end = (ulong)s.PointerToRawData + (ulong)s.SizeOfRawData;
        if (s.SizeOfRawData > 0 && end <= (ulong)bytes.Length)
        {
            ent = EntropyAnalyzer.Shannon(bytes.Slice((int)s.PointerToRawData, (int)s.SizeOfRawData));
        }

        entropyBySection[s.Name] = ent;

        Console.WriteLine($"  {s.Name,-8}   0x{s.SizeOfRawData:X6}   0x{s.PointerToRawData:X6}   {ent,7:F3}");
    }

    var imports = ImportParser.Parse(pe);

    Console.WriteLine();
    Console.WriteLine($"Imports: {imports.ModuleCount} module(s), {imports.FunctionCount} function(s)");
    foreach (var m in imports.Modules.Take(8))
        Console.WriteLine($"  - {m.Name} ({m.Functions.Count})");
    if (imports.Modules.Count > 8)
        Console.WriteLine("  ...");

    Console.WriteLine();

    var heur = PackerHeuristics.Evaluate(pe, entropyBySection, imports);

    Console.WriteLine($"Packed-likelihood score: {heur.Score}/100");
    Console.WriteLine($"Likely packed: {(heur.LikelyPacked ? "YES" : "NO")}");
    Console.WriteLine("Reasons:");
    foreach (var r in heur.Reasons)
        Console.WriteLine($"  - {r}");

    return 0;
}

static int CmdExtract(string[] args, string path)
{
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"File not found: {path}");
        return 2;
    }

    var outDir = GetArgValue(args, "--out");
    if (string.IsNullOrWhiteSpace(outDir))
    {
        Console.Error.WriteLine("Missing required option: --out <output-dir>");
        return 2;
    }

    double minEntropy = ParseDoubleOr(GetArgValue(args, "--min-entropy"), 6.6);
    int minSize = ParseIntOr(GetArgValue(args, "--min-size"), 4096);
    bool dumpAll = HasArg(args, "--all");

    Directory.CreateDirectory(outDir);

    var pe = PeFile.Load(path);
    var bytes = pe.AsSpan();

    var candidates = pe.Sections
        .Where(s => s.SizeOfRawData > 0)
        .Where(s =>
        {
            if (dumpAll) return true;
            if (s.SizeOfRawData < (uint)minSize) return false;

            if (IsInterestingSectionName(s.Name)) return true;
            if (s.Name.StartsWith("/", StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        })
        .Select(s => new
        {
            Section = s,
            FileOffset = (int)s.PointerToRawData,
            Size = (int)s.SizeOfRawData
        })
        .ToList();

    int dumped = 0;
    var manifest = new List<object>();

    foreach (var c in candidates)
    {
        ulong end = (ulong)c.FileOffset + (ulong)c.Size;
        if (end > (ulong)bytes.Length) continue;

        var blob = bytes.Slice(c.FileOffset, c.Size);
        double ent = EntropyAnalyzer.Shannon(blob);

        bool forced = dumpAll || IsInterestingSectionName(c.Section.Name) || c.Section.Name.StartsWith("/");
        if (!forced && ent < minEntropy)
            continue;

        var safeName = SanitizeName(c.Section.Name);
        var fileName = $"{dumped:D3}_{safeName}_off0x{c.FileOffset:X}_sz0x{c.Size:X}.bin";
        var outPath = Path.Combine(outDir, fileName);

        File.WriteAllBytes(outPath, blob.ToArray());

        var embeddedPes = FindEmbeddedPes(blob);

        manifest.Add(new
        {
            source = c.Section.Name,
            fileOffset = c.FileOffset,
            size = c.Size,
            entropy = ent,
            output = fileName,
            embeddedPEOffsets = embeddedPes
        });

        dumped++;
    }

    var manifestPath = Path.Combine(outDir, "manifest.json");
    File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

    Console.WriteLine($"Extracted {dumped} blob(s) to: {Path.GetFullPath(outDir)}");
    Console.WriteLine($"Manifest: {manifestPath}");
    if (!dumpAll)
        Console.WriteLine("Tip: add --all to dump all sections (useful for demos).");

    return 0;
}

static int CmdDecompress(string[] args, string targetPath)
{
    var outDir = GetArgValue(args, "--out");
    if (string.IsNullOrWhiteSpace(outDir))
    {
        Console.Error.WriteLine("Missing required option: --out <output-dir>");
        return 2;
    }

    int maxOut = ParseIntOr(GetArgValue(args, "--max-out"), 50 * 1024 * 1024);
    Directory.CreateDirectory(outDir);

    var inputs = ResolveInputs(targetPath);
    if (inputs is null) return 2;

    int totalOutputs = 0;

    Console.WriteLine($"Inputs: {inputs.Count}");
    Console.WriteLine($"Output dir: {Path.GetFullPath(outDir)}");
    Console.WriteLine();

    foreach (var inPath in inputs)
    {
        byte[] input = File.ReadAllBytes(inPath);
        var outputs = DeflateDecompressor.TryDecompressAll(input, maxOut);

        Console.WriteLine($"{Path.GetFileName(inPath)} -> decompress attempts: {outputs.Count}");

        int i = 0;
        foreach (var o in outputs)
        {
            var baseName = Path.GetFileNameWithoutExtension(inPath);
            var outName = $"{baseName}_inflate_{i:D2}_sz0x{o.Length:X}.bin";
            File.WriteAllBytes(Path.Combine(outDir, outName), o);

            totalOutputs++;
            i++;
        }
    }

    Console.WriteLine();
    Console.WriteLine($"Total decompressed outputs: {totalOutputs}");

    return 0;
}

static int CmdXor(string[] args, string targetPath)
{
    var outDir = GetArgValue(args, "--out");
    if (string.IsNullOrWhiteSpace(outDir))
    {
        Console.Error.WriteLine("Missing required option: --out <output-dir>");
        return 2;
    }

    double minEntropyDrop = ParseDoubleOr(GetArgValue(args, "--min-entropy-drop"), 0.7);
    bool requireMz = HasArg(args, "--require-mz");
    int topN = ParseIntOr(GetArgValue(args, "--top"), 10);
    bool full = HasArg(args, "--full");

    Directory.CreateDirectory(outDir);

    var inputs = ResolveInputs(targetPath);
    if (inputs is null) return 2;

    var top = new List<TopHit>();
    int totalOutputs = 0;

    Console.WriteLine($"Inputs: {inputs.Count}");
    Console.WriteLine($"Output dir: {Path.GetFullPath(outDir)}");
    Console.WriteLine($"Filters: minEntropyDrop={minEntropyDrop}, requireMz={requireMz}, top={topN}, full={full}");
    Console.WriteLine();

    foreach (var inPath in inputs)
    {
        byte[] input = File.ReadAllBytes(inPath);
        double entIn = EntropyAnalyzer.Shannon(input);

        var candidates = full ? XorUnpacker.TryCommonXors(input) : TryXorWithProbe(input);
        int keptForThisInput = 0;

        foreach (var cand in candidates)
        {
            double entOut = EntropyAnalyzer.Shannon(cand.Output);
            double drop = entIn - entOut;
            var peHits = FindEmbeddedPes(cand.Output);

            top.Add(new TopHit(Path.GetFileName(inPath), cand.Variant, cand.KeyDescription, drop, peHits.Count));

            bool interesting = (drop >= minEntropyDrop) || peHits.Count > 0;
            if (requireMz && peHits.Count == 0) interesting = false;

            if (!interesting) continue;

            var baseName = Path.GetFileNameWithoutExtension(inPath);
            var safeKey = cand.KeyDescription.Replace("=", "_").Replace(":", "_");
            var outName = SanitizeName($"{baseName}_{cand.Variant}_{safeKey}_drop{drop:F2}_pe{peHits.Count}_sz0x{cand.Output.Length:X}.bin");

            File.WriteAllBytes(Path.Combine(outDir, outName), cand.Output);

            keptForThisInput++;
            totalOutputs++;
        }

        Console.WriteLine($"{Path.GetFileName(inPath)} -> xor tried: {candidates.Count}, kept: {keptForThisInput}");
    }

    Console.WriteLine();
    Console.WriteLine($"Total XOR outputs kept: {totalOutputs}");

    Console.WriteLine();
    Console.WriteLine($"Top {topN} candidates by entropy drop:");
    foreach (var hit in top.OrderByDescending(x => x.EntropyDrop).Take(topN))
        Console.WriteLine($"  - {hit.Input} | {hit.Variant} {hit.Key} | drop={hit.EntropyDrop:F3} | peHits={hit.PeHits}");

    return 0;
}

static int CmdTriage(string[] args, string blobDir)
{
    if (!Directory.Exists(blobDir))
    {
        Console.Error.WriteLine($"Directory not found: {blobDir}");
        return 2;
    }

    var outDir = GetArgValue(args, "--out");
    if (string.IsNullOrWhiteSpace(outDir))
    {
        Console.Error.WriteLine("Missing required option: --out <output-dir>");
        return 2;
    }

    int topN = ParseIntOr(GetArgValue(args, "--top"), 15);
    double minScore = ParseDoubleOr(GetArgValue(args, "--min-score"), 10);
    int maxOut = ParseIntOr(GetArgValue(args, "--max-out"), 50 * 1024 * 1024);
    bool fullXor = HasArg(args, "--full-xor");

    Directory.CreateDirectory(outDir);

    var inputs = Directory.GetFiles(blobDir, "*.bin", SearchOption.TopDirectoryOnly)
        .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
        .ToList();

    Console.WriteLine($"Inputs: {inputs.Count}");
    Console.WriteLine($"Output dir: {Path.GetFullPath(outDir)}");
    Console.WriteLine($"Options: top={topN}, minScore={minScore}, maxOut={maxOut}, fullXor={fullXor}");
    Console.WriteLine();

    var results = new List<TriageResult>();
    int emitted = 0;

    foreach (var inPath in inputs)
    {
        byte[] input = File.ReadAllBytes(inPath);
        double entIn = EntropyAnalyzer.Shannon(input);
        string inName = Path.GetFileName(inPath);

        // Deflate attempts
        foreach (var o in DeflateDecompressor.TryDecompressAll(input, maxOut))
        {
            var tr = ScoreResult(inName, "deflate", "auto", input, o, entIn);
            tr.OutputFile = Emit(outDir, ref emitted, inName, tr.Engine, tr.Variant, o);
            results.Add(tr);
        }

        // XOR attempts
        var xorCandidates = fullXor ? XorUnpacker.TryCommonXors(input) : TryXorWithProbe(input);
        foreach (var c in xorCandidates)
        {
            if (c.Variant == "xor-1byte" && string.Equals(c.KeyDescription, "0x00", StringComparison.OrdinalIgnoreCase))
                continue;

            var tr = ScoreResult(inName, "xor", $"{c.Variant}:{c.KeyDescription}", input, c.Output, entIn);

            if (tr.Score >= 25 || tr.PeHits > 0)
                tr.OutputFile = Emit(outDir, ref emitted, inName, tr.Engine, tr.Variant, c.Output);

            results.Add(tr);
        }
    }

    var manifestPath = Path.Combine(outDir, "triage_manifest.json");
    File.WriteAllText(manifestPath, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));

    int peHitCount = results.Count(r => r.PeHits > 0);
    double bestDrop = results.Count > 0 ? results.Max(r => r.EntropyDrop) : 0;

    Console.WriteLine($"Generated results: {results.Count}");
    Console.WriteLine($"Manifest: {manifestPath}");
    Console.WriteLine($"Summary: peHitResults={peHitCount}, bestEntropyDrop={bestDrop:F3}, emittedFiles={emitted}");
    Console.WriteLine();

    var filteredTop = results
        .Where(r => r.PeHits > 0 || r.Score >= minScore)
        .OrderByDescending(r => r.Score)
        .Take(topN)
        .ToList();

    if (filteredTop.Count == 0)
    {
        Console.WriteLine($"Top {topN} candidates by score: (none met minScore={minScore} and no PE hits)");
        return 0;
    }

    Console.WriteLine($"Top {topN} candidates by score (filtered: Score>= {minScore} OR peHits>0):");
    foreach (var r in filteredTop)
    {
        Console.WriteLine($"  - score={r.Score,7:F1} | peHits={r.PeHits} | drop={r.EntropyDrop,7:F3} | {r.Input} | {r.Engine}:{r.Variant} | out={r.OutputFile ?? "(not emitted)"}");
    }

    return 0;
}

// ---------------- Helpers ----------------

static bool IsInterestingSectionName(string name)
{
    return name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase)
        || name.Equals(".tls", StringComparison.OrdinalIgnoreCase)
        || name.Equals(".idata", StringComparison.OrdinalIgnoreCase)
        || name.Equals(".reloc", StringComparison.OrdinalIgnoreCase);
}

static string SanitizeName(string s)
{
    var invalid = Path.GetInvalidFileNameChars();
    var chars = s.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray();
    var cleaned = new string(chars);
    return string.IsNullOrWhiteSpace(cleaned) ? "out" : cleaned;
}

static List<string>? ResolveInputs(string path)
{
    var inputs = new List<string>();

    if (File.Exists(path))
    {
        inputs.Add(path);
        return inputs;
    }

    if (Directory.Exists(path))
    {
        inputs.AddRange(Directory.GetFiles(path, "*.bin", SearchOption.TopDirectoryOnly)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
        return inputs;
    }

    Console.Error.WriteLine($"File or directory not found: {path}");
    return null;
}

static List<int> FindEmbeddedPes(ReadOnlySpan<byte> blob)
{
    var hits = new List<int>();

    for (int i = 0; i <= blob.Length - 0x40; i++)
    {
        if (blob[i] != (byte)'M' || blob[i + 1] != (byte)'Z')
            continue;

        int e_lfanewOff = i + 0x3C;
        if (e_lfanewOff + 4 > blob.Length) continue;

        int e_lfanew = BitConverter.ToInt32(blob.Slice(e_lfanewOff, 4));
        if (e_lfanew <= 0) continue;

        int peSigOff = i + e_lfanew;
        if (peSigOff + 4 > blob.Length) continue;

        if (blob[peSigOff] == (byte)'P' && blob[peSigOff + 1] == (byte)'E' && blob[peSigOff + 2] == 0 && blob[peSigOff + 3] == 0)
            hits.Add(i);
    }

    return hits;
}

static IReadOnlyList<XorCandidate> TryXorWithProbe(byte[] input)
{
    int probeLen = Math.Min(input.Length, 4096);
    var probe = new byte[probeLen];
    Buffer.BlockCopy(input, 0, probe, 0, probeLen);

    double entInProbe = EntropyAnalyzer.Shannon(probe);
    var promisingKeys = new List<byte>();

    for (int k = 0; k <= 0xFF; k++)
    {
        byte key = (byte)k;
        var tmp = new byte[probeLen];
        for (int i = 0; i < probeLen; i++)
            tmp[i] = (byte)(probe[i] ^ key);

        var mzHits = FindEmbeddedPes(tmp);
        double entOutProbe = EntropyAnalyzer.Shannon(tmp);
        double drop = entInProbe - entOutProbe;

        if (mzHits.Count > 0 || drop >= 0.8)
            promisingKeys.Add(key);
    }

    foreach (var k in new byte[] { 0x00, 0xFF, 0x5A, 0xA5, 0xAA, 0x55 })
        if (!promisingKeys.Contains(k)) promisingKeys.Add(k);

    var results = new List<XorCandidate>();

    foreach (var key in promisingKeys.Distinct())
    {
        var outBuf = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
            outBuf[i] = (byte)(input[i] ^ key);

        results.Add(new XorCandidate("xor-1byte", $"0x{key:X2}", outBuf));
    }

    foreach (var cand in XorUnpacker.TryCommonXors(input).Where(c => c.Variant == "xor-rolling-key"))
        results.Add(cand);

    return results;
}

static TriageResult ScoreResult(string inputName, string engine, string variant, byte[] input, byte[] output, double entIn)
{
    double entOut = EntropyAnalyzer.Shannon(output);
    double drop = entIn - entOut;
    var peHits = FindEmbeddedPes(output);

    double score = 0;

    if (peHits.Count > 0) score += 1000;
    if (StartsWithMz(output)) score += 250;

    if (drop > 0) score += drop * 100;
    if (drop < 0) score += drop * 25;

    if (Math.Abs(drop) < 0.0001 && peHits.Count == 0) score -= 5;

    return new TriageResult
    {
        Input = inputName,
        Engine = engine,
        Variant = variant,
        InputSize = input.Length,
        OutputSize = output.Length,
        InputEntropy = entIn,
        OutputEntropy = entOut,
        EntropyDrop = drop,
        PeHits = peHits.Count,
        PeHitOffsets = peHits,
        Score = score
    };
}

static bool StartsWithMz(ReadOnlySpan<byte> b)
    => b.Length >= 2 && b[0] == (byte)'M' && b[1] == (byte)'Z';

static string Emit(string outDir, ref int n, string inputName, string engine, string variant, byte[] output)
{
    var baseName = Path.GetFileNameWithoutExtension(inputName);
    var safeVariant = SanitizeName(variant.Replace(":", "_"));
    var name = $"{n:D4}_{baseName}_{engine}_{safeVariant}_sz0x{output.Length:X}.bin";
    File.WriteAllBytes(Path.Combine(outDir, name), output);
    n++;
    return name;
}

sealed class TriageResult
{
    public string Input { get; set; } = "";
    public string Engine { get; set; } = "";
    public string Variant { get; set; } = "";

    public int InputSize { get; set; }
    public int OutputSize { get; set; }

    public double InputEntropy { get; set; }
    public double OutputEntropy { get; set; }
    public double EntropyDrop { get; set; }

    public int PeHits { get; set; }
    public List<int> PeHitOffsets { get; set; } = new();

    public double Score { get; set; }
    public string? OutputFile { get; set; }
}

sealed record TopHit(string Input, string Variant, string Key, double EntropyDrop, int PeHits);
