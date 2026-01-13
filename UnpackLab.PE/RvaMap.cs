namespace UnpackLab.PE;

public static class RvaMap
{
    public static bool TryRvaToFileOffset(IReadOnlyList<Section> sections, uint rva, out int fileOffset)
    {
        foreach (var s in sections)
        {
            uint start = s.VirtualAddress;
            uint end = start + Math.Max(s.VirtualSize, s.SizeOfRawData);

            if (rva >= start && rva < end)
            {
                uint delta = rva - start;
                fileOffset = (int)(s.PointerToRawData + delta);
                return true;
            }
        }

        fileOffset = 0;
        return false;
    }
}
