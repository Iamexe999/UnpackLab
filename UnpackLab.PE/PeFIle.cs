using System.Buffers.Binary;

namespace UnpackLab.PE;

public sealed class PeFile
{
    public string Path { get; }
    public IReadOnlyList<Section> Sections => _sections;

    public bool Is64Bit { get; private set; }
    public uint AddressOfEntryPoint { get; private set; }
    public ushort NumberOfSections { get; private set; }

    // Import Directory (DataDirectory[1])
    public uint ImportDirectoryRva { get; private set; }
    public uint ImportDirectorySize { get; private set; }

    private readonly List<Section> _sections = new();
    private readonly byte[] _data;

    private PeFile(string path, byte[] data)
    {
        Path = path;
        _data = data;
        Parse();
    }

    public static PeFile Load(string path)
        => new(path, File.ReadAllBytes(path));

    public ReadOnlySpan<byte> AsSpan() => _data;

    private void Parse()
    {
        var span = _data.AsSpan();

        // DOS header
        if (span.Length < 0x40) throw new InvalidDataException("File too small for DOS header.");
        if (BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(0, 2)) != 0x5A4D) // "MZ"
            throw new InvalidDataException("Missing MZ header.");

        int e_lfanew = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0x3C, 4));
        if (e_lfanew <= 0 || e_lfanew + 4 > span.Length)
            throw new InvalidDataException("Invalid e_lfanew.");

        // NT headers signature "PE\0\0"
        if (BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(e_lfanew, 4)) != 0x00004550)
            throw new InvalidDataException("Missing PE header.");

        int fileHeaderOff = e_lfanew + 4;
        if (fileHeaderOff + 20 > span.Length)
            throw new InvalidDataException("Truncated FILE_HEADER.");

        NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(fileHeaderOff + 2, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(fileHeaderOff + 16, 2));

        int optionalOff = fileHeaderOff + 20;
        if (optionalOff + sizeOfOptionalHeader > span.Length)
            throw new InvalidDataException("Truncated OPTIONAL_HEADER.");

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(optionalOff, 2));
        Is64Bit = magic == 0x20B; // PE32+ (0x20B), PE32 (0x10B)
        if (magic != 0x20B && magic != 0x10B)
            throw new InvalidDataException("Unknown PE optional header magic.");

        AddressOfEntryPoint = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(optionalOff + 16, 4));

        // DataDirectory starts at:
        // PE32:  optionalOff + 96
        // PE32+: optionalOff + 112
        int dataDirOff = optionalOff + (Is64Bit ? 112 : 96);

        // Import Directory is index 1; each entry is 8 bytes: RVA (4) + Size (4)
        int importEntryOff = dataDirOff + (1 * 8);
        if (importEntryOff + 8 <= span.Length)
        {
            ImportDirectoryRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(importEntryOff, 4));
            ImportDirectorySize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(importEntryOff + 4, 4));
        }

        // Section headers begin immediately after optional header
        int sectionTableOff = optionalOff + sizeOfOptionalHeader;
        const int sectionSize = 40;

        for (int i = 0; i < NumberOfSections; i++)
        {
            int off = sectionTableOff + i * sectionSize;
            if (off + sectionSize > span.Length)
                throw new InvalidDataException("Truncated section table.");

            _sections.Add(Section.Parse(span.Slice(off, sectionSize)));
        }
    }
}
