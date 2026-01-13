using System.Buffers.Binary;
using System.Text;

namespace UnpackLab.PE;

public sealed record Section(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint Characteristics)
{
    public static Section Parse(ReadOnlySpan<byte> sh)
    {
        string name = Encoding.ASCII.GetString(sh.Slice(0, 8)).TrimEnd('\0');

        uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(sh.Slice(8, 4));
        uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(sh.Slice(12, 4));
        uint sizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(sh.Slice(16, 4));
        uint ptrRaw = BinaryPrimitives.ReadUInt32LittleEndian(sh.Slice(20, 4));
        uint chars = BinaryPrimitives.ReadUInt32LittleEndian(sh.Slice(36, 4));

        return new Section(name, virtualSize, virtualAddress, sizeOfRawData, ptrRaw, chars);
    }
}
