using System.Buffers.Binary;

// Slightly modified ChaCha20 implementation for [FactoryGame]
public sealed class StreamingChaCha20
{
    private readonly uint[] _state = new uint[16];
    private readonly uint[] _x = new uint[16];
    private readonly byte[] _keystream = new byte[64];
    private int _ksIndex;
    private readonly ulong _baseCounter64;

    public StreamingChaCha20(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce12, uint counter)
    {
        if (key32.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key32));
        if (nonce12.Length != 12)
            throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce12));

        _state[0] = 0x61707865;
        _state[1] = 0x3320646e;
        _state[2] = 0x79622d32;
        _state[3] = 0x6b206574;

        for (int i = 0; i < 8; i++)
            _state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key32.Slice(i * 4, 4));

        _state[12] = counter;

        _state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(0, 4));
        _state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(4, 4));
        _state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(8, 4));

        _baseCounter64 = ((ulong)_state[13] << 32) | _state[12];
        _ksIndex = 64;
    }

    public void Xor(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < input.Length)
            throw new ArgumentException("Output span too small", nameof(output));

        for (int i = 0; i < input.Length; i++)
        {
            if (_ksIndex == 64)
                GenerateKeystreamBlock();

            output[i] = (byte)(input[i] ^ _keystream[_ksIndex]);
            _ksIndex++;
        }
    }

    public void XorInPlace(Span<byte> buffer) => Xor(buffer, buffer);

    public void Seek(ulong processedIdx)
    {
        ulong blockOffset = processedIdx >> 6;           // / 64
        int inBlock = (int)(processedIdx & 0x3FUL);      // & 63

        ulong counter64 = _baseCounter64 + blockOffset;
        _state[12] = (uint)counter64;
        _state[13] = (uint)(counter64 >> 32);

        GenerateKeystreamBlock_NoAdvance();
        _ksIndex = inBlock;
    }

    public uint CounterLow => _state[12];
    public uint CounterHighOrNonce0 => _state[13];
    public int KeystreamIndex => _ksIndex == 64 ? 0 : _ksIndex;

    private void GenerateKeystreamBlock()
    {
        GenerateKeystreamBlock_NoAdvance();

        _state[12] = unchecked(_state[12] + 1);
        if (_state[12] == 0)
            _state[13] = unchecked(_state[13] + 1);

        _ksIndex = 0;
    }

    private void GenerateKeystreamBlock_NoAdvance()
    {
        for (int i = 0; i < 16; i++)
            _x[i] = _state[i];

        for (int r = 0; r < 10; r++)
        {
            QuarterRound(ref _x[0], ref _x[4], ref _x[8], ref _x[12]);
            QuarterRound(ref _x[1], ref _x[5], ref _x[9], ref _x[13]);
            QuarterRound(ref _x[2], ref _x[6], ref _x[10], ref _x[14]);
            QuarterRound(ref _x[3], ref _x[7], ref _x[11], ref _x[15]);

            QuarterRound(ref _x[0], ref _x[5], ref _x[10], ref _x[15]);
            QuarterRound(ref _x[1], ref _x[6], ref _x[11], ref _x[12]);
            QuarterRound(ref _x[2], ref _x[7], ref _x[8], ref _x[13]);
            QuarterRound(ref _x[3], ref _x[4], ref _x[9], ref _x[14]);
        }

        for (int i = 0; i < 16; i++)
        {
            uint v = unchecked(_x[i] + _state[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(_keystream.AsSpan(i * 4, 4), v);
        }
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a = unchecked(a + b); d ^= a; d = RotL(d, 16);
        c = unchecked(c + d); b ^= c; b = RotL(b, 12);
        a = unchecked(a + b); d ^= a; d = RotL(d, 8);
        c = unchecked(c + d); b ^= c; b = RotL(b, 7);
    }

    private static uint RotL(uint v, int n) => (v << n) | (v >> (32 - n));
}
