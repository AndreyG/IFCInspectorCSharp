using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace IFCInspector;

unsafe struct SHA256
{
    public const int Length = 32;
    public fixed byte Data[Length];
}

enum Version : byte { }

enum Abi : byte { }

enum Architecture : byte
{
    Unknown         = 0x00, // Unknown target
    X86             = 0x01, // x86 (32-bit) target
    X64             = 0x02, // x64 (64-bit) target
    ARM32           = 0x03, // ARM (32-bit) target
    ARM64           = 0x04, // ARM (64-bit) target
    HybridX86ARM64  = 0x05, // Hybrid x86-arm64
}

enum LanguageVersion : uint { }

enum UnitSort
{
    Source      = 0x00,
    Primary     = 0x01,
    Partition   = 0x02,
    Header      = 0x03,
    ExportedTU  = 0x04,
}

enum ByteOffset : uint { }
enum TextOffset : uint { }

enum Cardinality : uint { }

enum EntitySize : uint { }

readonly struct UnitIndex
{
    private readonly uint _data;

    public UnitSort Sort() => (UnitSort)(_data & 0x7);
}

enum ScopeIndex : uint { }

struct PartitionSummary
{
    public TextOffset Name;
    public ByteOffset Offset;
    public Cardinality Cardinality;
    public EntitySize EntrySize;

    public uint SizeBytes => (uint)Cardinality * (uint)EntrySize;
}

struct FileHeader
{
    public SHA256 Checksum;
    public Version MajorVersion, MinorVersion;
    public Abi Abi;
    public Architecture Arch;
    public LanguageVersion Dialect;
    public ByteOffset StringTableBytes;
    public Cardinality StringTableSize;
    public UnitIndex Unit;
    public TextOffset SrcPath;
    public ScopeIndex GlobalScope;
    public ByteOffset TOC;
    public Cardinality PartitionCount;
    public bool Internal;
}

class File
{
    public const int SignatureLength = 4;
    private static readonly byte[] CanonicalFileSignature = { 0x54, 0x51, 0x45, 0x1A };

    private readonly SafeBuffer _buffer;
    private readonly FileHeader _header;

    public File(SafeBuffer buffer)
    {
        Span<byte> signature = stackalloc byte[SignatureLength];
        buffer.ReadSpan(0, signature);
        if (!signature.SequenceEqual(CanonicalFileSignature))
            throw new Exception("IFC file has invalid signature");

        _buffer = buffer;
        _header = buffer.Read<FileHeader>(SignatureLength);
    }

    public unsafe ReadOnlySpan<byte> Checksum()
    {
        fixed (byte* ptr = _header.Checksum.Data)
            return new ReadOnlySpan<byte>(ptr, SHA256.Length);
    }

    public unsafe ReadOnlySpan<PartitionSummary> TableOfContents()
    {
        return new ReadOnlySpan<PartitionSummary>(GetPointer(_header.TOC), (int)_header.PartitionCount);
    }

    public void PresentHeader()
    {
        Console.WriteLine($"IFC Version: {_header.MajorVersion}.{_header.MinorVersion}");
        Console.WriteLine($"Architecture: {_header.Arch}");
        Console.WriteLine($"Unit Sort: {_header.Unit.Sort()}");
        Console.WriteLine($"Source Path: {GetString(_header.SrcPath)}");
    }

    public unsafe string GetString(TextOffset offset)
    {
        var ptr = (sbyte*)GetPointer(_header.StringTableBytes) + (uint)offset;
        return new string(ptr);
    }

    public unsafe long CalcSize()
    {
        var result = SignatureLength + sizeof(FileHeader) + (uint)_header.StringTableSize;
        var toc = TableOfContents();
        result += toc.Length * sizeof(PartitionSummary);
        foreach (var partition in toc)
            result += partition.SizeBytes;
        return result;
    }

    private unsafe void* GetPointer(ByteOffset offset)
    {
        var ptr = (byte*)_buffer.DangerousGetHandle().ToPointer();
        ptr += (uint)offset;
        return ptr;
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: .ifc file");
            Environment.Exit(1);
        }

        var filepath = args[0];

        using var mmf = MemoryMappedFile.CreateFromFile(filepath, FileMode.Open);
        using var accessor = mmf.CreateViewAccessor();
        using var handle = accessor.SafeMemoryMappedViewHandle;

        var file = new File(handle);
        file.PresentHeader();

        var fileLength = new FileInfo(filepath).Length;

        if (!file.Checksum().SequenceEqual(CalculateFileChecksum(mmf, fileLength)))
            throw new Exception("Corrupted File: checksum differs from expected one");

        if (file.CalcSize() != fileLength)
            throw new Exception("Corrupted File: length differs from expected one");

        Console.WriteLine("--- Partitions --- ");
        foreach (var partition in file.TableOfContents())
            Console.WriteLine(file.GetString(partition.Name));
    }

    private static ReadOnlySpan<byte> CalculateFileChecksum(MemoryMappedFile mmf, long fileLength)
    {
        const int contentOffset = File.SignatureLength + SHA256.Length;
        using var stream = mmf.CreateViewStream(contentOffset, fileLength - contentOffset);
        using var sha256Hash = System.Security.Cryptography.SHA256.Create();
        return sha256Hash.ComputeHash(stream);
    }
}