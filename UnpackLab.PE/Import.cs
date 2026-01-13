using System.Buffers.Binary;
using System.Text;

namespace UnpackLab.PE;

public sealed record ImportModule(string Name, IReadOnlyList<string> Functions);

public sealed record ImportTable(IReadOnlyList<ImportModule> Modules)
{
    public int ModuleCount => Modules.Count;
    public int FunctionCount => Modules.Sum(m => m.Functions.Count);
}

public static class ImportParser
{
    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes.
    public static ImportTable Parse(PeFile pe)
    {
        if (pe.ImportDirectoryRva == 0 || pe.ImportDirectorySize == 0)
            return new ImportTable(Array.Empty<ImportModule>());

        var data = pe.AsSpan();
        if (!RvaMap.TryRvaToFileOffset(pe.Sections, pe.ImportDirectoryRva, out var impOff))
            return new ImportTable(Array.Empty<ImportModule>());

        var modules = new List<ImportModule>();

        while (true)
        {
            if (impOff + 20 > data.Length) break;

            uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(impOff + 0, 4));
            uint timeDateStamp      = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(impOff + 4, 4));
            uint forwarderChain     = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(impOff + 8, 4));
            uint nameRva            = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(impOff + 12, 4));
            uint firstThunk         = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(impOff + 16, 4));

            // Null descriptor terminates
            if (originalFirstThunk == 0 && timeDateStamp == 0 && forwarderChain == 0 && nameRva == 0 && firstThunk == 0)
                break;

            string dllName = ReadAsciiZ(pe, nameRva) ?? "<invalid>";

            // Use OFT if present, else FT
            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var funcs = ReadThunkNames(pe, thunkRva);

            modules.Add(new ImportModule(dllName, funcs));
            impOff += 20;
        }

        return new ImportTable(modules);
    }

    private static List<string> ReadThunkNames(PeFile pe, uint thunkRva)
    {
        var funcs = new List<string>();
        if (thunkRva == 0) return funcs;

        var data = pe.AsSpan();
        if (!RvaMap.TryRvaToFileOffset(pe.Sections, thunkRva, out var off))
            return funcs;

        bool is64 = pe.Is64Bit;
        int stride = is64 ? 8 : 4;

        for (int i = 0; i < 4096; i++) // hard cap
        {
            int entryOff = off + i * stride;
            if (entryOff + stride > data.Length) break;

            ulong val = is64
                ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(entryOff, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(entryOff, 4));

            if (val == 0) break;

            bool isOrdinal = is64
                ? (val & 0x8000_0000_0000_0000UL) != 0
                : (val & 0x8000_0000UL) != 0;

            if (isOrdinal)
            {
                ushort ord = (ushort)(val & 0xFFFF);
                funcs.Add($"#ORD{ord}");
                continue;
            }

            uint ibnRva = (uint)(val & 0x7FFF_FFFF_FFFF_FFFFUL);
            string? name = ReadImportByName(pe, ibnRva);
            funcs.Add(name ?? "<invalid>");
        }

        return funcs;
    }

    private static string? ReadImportByName(PeFile pe, uint rva)
    {
        var data = pe.AsSpan();
        if (!RvaMap.TryRvaToFileOffset(pe.Sections, rva, out var off))
            return null;

        if (off + 2 >= data.Length) return null;

        off += 2; // skip hint
        return ReadAsciiZFromOffset(data, off);
    }

    private static string? ReadAsciiZ(PeFile pe, uint rva)
    {
        var data = pe.AsSpan();
        if (!RvaMap.TryRvaToFileOffset(pe.Sections, rva, out var off))
            return null;

        return ReadAsciiZFromOffset(data, off);
    }

    private static string? ReadAsciiZFromOffset(ReadOnlySpan<byte> data, int off)
    {
        if (off < 0 || off >= data.Length) return null;

        int end = off;
        while (end < data.Length && data[end] != 0) end++;

        return Encoding.ASCII.GetString(data.Slice(off, end - off));
    }
}
