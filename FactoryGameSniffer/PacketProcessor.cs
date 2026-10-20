using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using CSHead = Proto.CSHead;

namespace FactoryGameSniffer;

public class PacketProcessor
{
    static StreamingChaCha20? forDecryptingCS;
    static StreamingChaCha20? forDecryptingSC;
    static string privateKeyB64 = "MIICXwIBAAKBgQDZzQ1I1YbpehALLFCDe5rAxGvNfl6fehRrCCfmvBtWk4cQP1EyzkPeudYPoA0L4Z8FPMnB57NimwKvPL7VuzSjqTqYbr0q8rVY70eR1SPnXBn0D/mYPwF+pZMFvZ2iU0E6ADO4N14Px9VTq+/lWucX1IcCmr3NBBNVUXhxWnEAawIDAQABAoGBALq84oz19owryaGqxwVUbuSkBEHV/U8Cnor+HSfpVA8wwfaeMwI6c1p9Pxl6gnUTZwJYkiuceuMqQGz6yiv6LDAoiLMZ7MpRAcQYeDYKq3gjZDrXhpTFVGciEy/D1bd1YI51RGlWJAbo47wQTjTL15quAecqYdmDMqUrfCWOAhGRAkEA+lDvuB+mAvd9bjl8WQG6QRDrmaCAiSVNL5vJTOa8+vhNzSia0esxMEYvPMkYXhA1w4deHFd2dSsqULkveJBZ7wJBAN6/G6FbjozubZzvqCWN1tbEVknbZrFvfFKE08j085BJalriz1mY0zdViEOyC14nMX85HYbAM1hMXs3ALESibUUCQQCHTPhGLdUuBVhnG+t6sNRcFylCAN95QhBWi35jctTzUwO6wRfuH5KW5VjjIk9piJmG9sSHzT7aVlqpB3ABWwVBAkEAkHST8LM14YQHJk3uWFyCRcoSw9c75DqO/90QlDT3eE2EYejR3CNWZ35a3rwqzybP3Ngno+ol4k+08+57Rw+nmQJBAMMjv4/XM/KX126fs0/wevFvFE4Lg76PXChX5uSHpWwZmKuKtdxZ/L3MA9Ys3MNbWXK8UL5sv39Ch6BCCYLTUYo=";

    // Well at least ChaCha20 has private key in the game client :)
    static RSA privateKey = RsaCryptoUtils.CreateRsaFromPkcs1Base64(privateKeyB64);

    // Dear lord please forgive me for this, but I couldn't find a better way to store the modulus
    private static readonly BigInteger SRSAModulus = new(
        Convert.FromHexString(
            "CD 51 D4 ED 50 A3 5E 47 B5 EE D6 A7 97 8B DD FC BD D0 6B 9C 08 59 38 F6 7B B8 FA 7A 55 B1 B5 02 59 07 21 FC 06 B4 EC 71 9A 3C 6B 96 70 74 D5 9A 40 24 07 12 DB 4E F3 40 48 3A E9 E1 DC 02 1F B8 0C 58 4A 6F 53 A0 F3 D3 9E FA 57 B5 36 B4 02 B2 6F 8F F1 A8 7A E0 09 D0 7B A5 B0 F9 1A 5D B3 BC 1E 35 70 3C 34 12 71 02 62 1C 1E A4 FF 7E 81 71 82 8B F4 B7 5D 93 E0 ED 3F E8 09 A0 2A 0B 26 82 65 F2 7A 68 21 80 CE AB 5F 89 B5 F1 3C 60 9A D1 5E 2B AA 40 C7 64 81 2E 60 81 4F E8 CB 23 64 60 8F 64 16 DE 5F 5B 42 70 91 B1 5C 7F BE 1D DD 54 B7 AA 09 9F 96 54 BE AB FD 64 0E 73 E5 80 F9 54 40 24 33 4F ED D7 74 28 C5 94 78 89 FD B1 83 A0 B0 FB 0D 2C AD 3E 3E B9 82 E2 04 52 64 29 6F 3D 68 0F 45 43 14 D4 DB 7D 8C 2A 05 5A 68 22 D9 14 6A 80 DC 0E D9 7C A3 C6 E6 B7 79 5D 02 AC 8F C0"
            .Replace(" ", string.Empty) // too lazy to do it myself
        ),
        isUnsigned: true, isBigEndian: false
    );

    private static readonly object FragmentLock = new();
    private static readonly Dictionary<FragmentKey, FragmentAccumulator> FragmentBuffers = new();

    // That's where all the fun is
    public static void ProcessPacket(byte[] packetData, PacketDirection direction, StreamWriter writer, Action<DecodedPacket>? onDecoded = null)
    {
        if (packetData.Length < 3)
            throw new InvalidDataException("Truncated packet frame");

        using Stream stream = new MemoryStream(packetData, writable: false);
        using BinaryReader reader = new BinaryReader(stream);
        byte headLen = reader.ReadByte();
        ushort bodyLen = reader.ReadUInt16();
        if (headLen == 0 || packetData.Length != 3 + headLen + bodyLen)
            throw new InvalidDataException($"Invalid frame sizes: header={headLen}, body={bodyLen}, actual={packetData.Length}");

        byte[] head = reader.ReadBytes(headLen);
        byte[] body = reader.ReadBytes(bodyLen);

        if (TryReadLoginHeader(head, direction, out int loginId))
        {
            // We skip CS_LOGIN as it's not decryptable with public key (private key leak when?)
            if (direction == PacketDirection.CS)
                return;

            byte[] loginBody = DecryptSRSA(body);
            InitChaCha(loginBody);

            (string name, string json) = GoogleProtoDecoder.Decode(loginId, direction, loginBody);
            writer.WriteLine($"[{direction}] {name}: {json}");
            onDecoded?.Invoke(new DecodedPacket(direction, loginId, name, packetData.Length, json));
            return;
        }

        StreamingChaCha20? chacha = direction == PacketDirection.CS ? forDecryptingCS : forDecryptingSC;
        if (chacha is null)
            throw new InvalidOperationException("ChaCha20 not initialized; start capture before game login");

        byte[] decryptedHead = new byte[head.Length];
        byte[] decryptedBody = new byte[body.Length];
        chacha.Xor(head, decryptedHead);
        chacha.Xor(body, decryptedBody);

        CSHead parsedHead = CSHead.Parser.ParseFrom(decryptedHead);
        if (parsedHead.IsCompress)
            decryptedBody = DecompressLZ4(decryptedBody);

        if (parsedHead.TotalPackCount > 1)
        {
            if (!TryAssembleFragments(parsedHead, decryptedBody, direction, out CSHead assembledHead, out byte[] assembledBody))
                return;
            parsedHead = assembledHead;
            decryptedBody = assembledBody;
        }

        ProcessBody(parsedHead, decryptedBody, decryptedHead.Length, writer, direction, onDecoded);
    }

    private static bool TryReadLoginHeader(byte[] header, PacketDirection direction, out int id)
    {
        id = direction == PacketDirection.CS ? 13 : 1;
        try
        {
            CSHead loginHeader = CSHead.Parser.ParseFrom(header);
            return loginHeader.Msgid == id;
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }

    // ChaCha20 is initialized from the server's SC_LOGIN response, which contains the encrypted key and nonce
    public static void InitChaCha(byte[] decodedLoginBody)
    {
        MessageDescriptor loginDescriptor = Proto.Game164Reflection.Descriptor.MessageTypes.Single(m => m.Name == "MSG_B1");
        IMessage rsp = loginDescriptor.Parser.ParseFrom(decodedLoginBody);
        byte[] f3 = ((ByteString)loginDescriptor.FindFieldByName("f3").Accessor.GetValue(rsp)).ToByteArray();
        byte[] f4 = ((ByteString)loginDescriptor.FindFieldByName("f4").Accessor.GetValue(rsp)).ToByteArray();
        byte[] key = privateKey.Decrypt(f3, RSAEncryptionPadding.Pkcs1);
        forDecryptingCS = new StreamingChaCha20(key, f4, 1);
        forDecryptingSC = new StreamingChaCha20(key, f4, 1);
    }

    private static byte[] DecryptSRSA(ReadOnlySpan<byte> input)
    {
        if (input.Length != 272)
            throw new InvalidDataException($"Invalid SRSA input length: {input.Length}");

        int outputLength = BinaryPrimitives.ReadInt32LittleEndian(input.Slice(8, 4));
        if (outputLength <= 0 || outputLength > 4096)
            throw new InvalidDataException($"Invalid SRSA output length: {outputLength}");

        BigInteger ciphertext = new(input.Slice(16, 256), isUnsigned: true, isBigEndian: true);
        byte[] plaintext = BigInteger.ModPow(ciphertext, 65537, SRSAModulus).ToByteArray(isUnsigned: true, isBigEndian: false);

        byte[] result = new byte[outputLength];
        Array.Copy(plaintext, result, Math.Min(plaintext.Length, result.Length));
        return result;
    }

    private static void ProcessBody(CSHead head, byte[] body, int headerLength, StreamWriter writer, PacketDirection direction, Action<DecodedPacket>? onDecoded)
    {
        (string packetName, string json) = GoogleProtoDecoder.Decode(head.Msgid, direction, body);
        writer.WriteLine($"[{direction}] {packetName}: {json}");
        onDecoded?.Invoke(new DecodedPacket(direction, head.Msgid, packetName, headerLength + body.Length, json));
    }

    private static byte[] DecompressLZ4(byte[] body)
    {
        Span<byte> decompressed = new byte[body.Length * 1000].AsSpan();
        int decompressLen = LZ4.Instance.Decompress(body, decompressed);
        return decompressed.Slice(0, decompressLen).ToArray();
    }

    private static bool TryAssembleFragments(CSHead head, byte[] decryptedBody, PacketDirection direction, out CSHead assembledHead, out byte[] assembledBody)
    {
        assembledHead = head;
        assembledBody = decryptedBody;

        uint total = head.TotalPackCount;
        uint partIndex = head.CurrentPackIndex;

        uint seq = direction == PacketDirection.SC ? (uint)head.DownSeqid : (uint)head.UpSeqid;
        uint baseSeq = seq - head.CurrentPackIndex;
        FragmentKey key = new((uint)head.Msgid, baseSeq, direction);

        lock (FragmentLock)
        {
            if (!FragmentBuffers.TryGetValue(key, out FragmentAccumulator? acc))
            {
                acc = new FragmentAccumulator(expectedCount: total, head);
                FragmentBuffers[key] = acc;
            }

            acc.Parts[partIndex] = decryptedBody;
            Console.WriteLine($"    fragment {partIndex + 1}/{total} msg={head.Msgid} keySeq={seq} parts={acc.Parts.Count}");

            if (acc.Parts.Count < acc.ExpectedCount)
                return false; // wait for more

            // ensure all parts present
            for (uint i = 0; i < acc.ExpectedCount; i++)
            {
                if (!acc.Parts.ContainsKey(i))
                    return false;
            }

            int totalLen = acc.Parts.Values.Sum(p => p.Length);
            byte[] combined = new byte[totalLen];

            int offset = 0;
            for (uint i = 0; i < acc.ExpectedCount; i++)
            {
                byte[] part = acc.Parts[i];
                Buffer.BlockCopy(part, 0, combined, offset, part.Length);
                offset += part.Length;
            }

            FragmentBuffers.Remove(key);

            assembledHead = acc.Head;
            assembledHead.TotalPackCount = 1;
            assembledHead.CurrentPackIndex = 0;
            assembledBody = combined;
            return true;
        }
    }
}

public readonly struct FragmentKey : IEquatable<FragmentKey>
{
    public readonly uint Msgid;
    public readonly uint Seq;
    public readonly PacketDirection Dir;

    public FragmentKey(uint msgid, uint seq, PacketDirection dir)
    {
        Msgid = msgid;
        Seq = seq;
        Dir = dir;
    }

    public bool Equals(FragmentKey other) => Msgid == other.Msgid && Seq == other.Seq && Dir == other.Dir;
    public override bool Equals(object? obj) => obj is FragmentKey other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Msgid, Seq, Dir);
}

internal sealed class FragmentAccumulator
{
    public uint ExpectedCount { get; }
    public CSHead Head { get; }
    public SortedDictionary<uint, byte[]> Parts { get; } = new();

    public FragmentAccumulator(uint expectedCount, CSHead head)
    {
        ExpectedCount = expectedCount;
        Head = head;
    }
}

public enum PacketDirection
{
    CS,
    SC
}

public readonly record struct DecodedPacket(PacketDirection Direction, int PacketId, string PacketName, int Length, string JsonData);
