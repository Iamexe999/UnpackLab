# UnpackLab

UnpackLab is a defensive malware analysis lab tool written in C#. It demonstrates how packed or obfuscated Windows PE files can be statically analyzed, partially unpacked using safe transforms, and triaged to identify embedded payloads.

This project does **not execute malware** and performs **no dynamic analysis**. All operations are based on static inspection, entropy analysis, and reversible decoding techniques.

---

## Features

### PE Analysis

* Parses PE32 and PE32+ binaries
* Displays architecture, entry point, section layout, and entropy
* Summarizes imported modules and functions
* Produces a heuristic packed-likelihood score

### Blob Extraction

* Extracts potentially interesting PE sections:

  * .rsrc, .tls, .idata, .reloc
  * unusually named sections (e.g. /19, /45)
* Filters by size and entropy
* Outputs raw blobs with a JSON manifest

### Safe Unpacking Transforms

* Deflate / zlib decompression attempts
* XOR decoding

  * single-byte XOR (key probing and common keys)
  * rolling XOR keys
* No execution of extracted data

### Triage and Scoring

* Runs unpacking transforms over extracted blobs
* Scores candidates using:

  * embedded PE header detection (MZ / PE signatures)
  * entropy reduction
  * structural indicators
* Outputs ranked results and machine-readable manifests

### Deterministic Demo Mode

* Generates safe synthetic blobs that reveal PE structure only after decoding
* Ensures reproducible demo output for testing and documentation

---

## Project Structure

```
UnpackLab
├── UnpackLab.Cli
│   └── Program.cs
│
├── UnpackLab.PE
│   ├── PeFile.cs
│   └── ImportParser.cs
│
├── UnpackLab.Heuristics
│   ├── EntropyAnalyzer.cs
│   └── PackerHeuristics.cs
│
├── UnpackLab.UnpackEngines
│   ├── DeflateDecompressor.cs
│   ├── XorUnpacker.cs
│   └── DemoSamples.cs
│
└── UnpackLab.Tests
    └── DemoPipelineTests.cs
```

---

## Build

```bash
dotnet build
```

---

## Usage

### Analyze a PE file

```bash
dotnet run --project UnpackLab.Cli -- analyze sample.exe
```

### Extract suspicious sections

```bash
dotnet run --project UnpackLab.Cli -- extract sample.exe --out blobs
```

### Triage extracted blobs

```bash
dotnet run --project UnpackLab.Cli -- triage blobs --out out\triage
```

---

## Demo (Guaranteed Positive Result)

UnpackLab includes a built-in demo generator that creates a safe XOR-obfuscated blob containing embedded PE markers.

### Generate demo blobs

```bash
dotnet run --project UnpackLab.Cli -- make-demo --out demo_blobs
```

### Run triage on demo blobs

```bash
dotnet run --project UnpackLab.Cli -- triage demo_blobs --out out\triage_demo --top 10 --min-score 10
```

### Example Output

```
Top candidates by score:
  - score=1250.0 | peHits=1 | demo_xor_embedded_pe_key0x5A.bin
    xor:xor-1byte:0x5A
```

This demonstrates the full pipeline:

1. Obfuscated data is identified
2. A decoding transform is applied
3. Embedded PE structure is recovered
4. Results are ranked correctly

---

## Tests

An end-to-end test validates the demo pipeline:

```bash
dotnet test
```

The test:

* Generates demo blobs
* Runs triage
* Asserts that at least one result contains embedded PE indicators

---

## Design Goals

* Defensive and educational focus
* No code execution
* Reproducible analysis
* Clear separation of parsing, heuristics, and unpacking logic
* Usable both as a learning tool and a portfolio project
