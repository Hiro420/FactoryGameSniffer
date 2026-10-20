namespace FactoryGameSniffer;

public class LZ4
{
    public static LZ4 Instance => new();

    public virtual int Decompress(ReadOnlySpan<byte> cmp, Span<byte> dec)
    {
        int cmpPos = 0;
        int decPos = 0;

        do
        {
            (int encCount, int litCount) = GetLiteralToken(cmp, ref cmpPos);

            litCount = GetLength(litCount, cmp, ref cmpPos);

            cmp.Slice(cmpPos, litCount).CopyTo(dec.Slice(decPos));

            cmpPos += litCount;
            decPos += litCount;

            if (cmpPos >= cmp.Length)
            {
                break;
            }

            int back = GetChunkEnd(cmp, ref cmpPos);

            encCount = GetLength(encCount, cmp, ref cmpPos) + 4;

            int encPos = decPos - back;

            if (encCount <= back)
            {
                dec.Slice(encPos, encCount).CopyTo(dec.Slice(decPos));

                decPos += encCount;
            }
            else
            {
                while (encCount-- > 0)
                {
                    dec[decPos++] = dec[encPos++];
                }
            }
        } while (cmpPos < cmp.Length && decPos < dec.Length);

        return decPos;
    }

    public virtual int DecompressWithDict(ReadOnlySpan<byte> cmp, Span<byte> dec, ReadOnlySpan<byte> dict)
    {
        int cmpPos = 0;
        int decPos = 0;

        do
        {
            (int encCount, int litCount) = GetLiteralToken(cmp, ref cmpPos);

            litCount = GetLength(litCount, cmp, ref cmpPos);

            cmp.Slice(cmpPos, litCount).CopyTo(dec.Slice(decPos));
            cmpPos += litCount;
            decPos += litCount;

            if (cmpPos >= cmp.Length)
                break;

            int back = GetChunkEnd(cmp, ref cmpPos);
            encCount = GetLength(encCount, cmp, ref cmpPos) + 4;

            int encPos = decPos - back;

            if (encPos >= 0)
            {
                if (encCount <= back)
                {
                    dec.Slice(encPos, encCount).CopyTo(dec.Slice(decPos));
                    decPos += encCount;
                }
                else
                {
                    while (encCount-- > 0)
                        dec[decPos++] = dec[encPos++];
                }
            }
            else
            {
                int dictPos = dict.Length + encPos;
                int dictAvail = dict.Length - dictPos;

                int fromDict = Math.Min(encCount, dictAvail);
                dict.Slice(dictPos, fromDict).CopyTo(dec.Slice(decPos));
                decPos += fromDict;
                encCount -= fromDict;

                if (encCount > 0)
                {
                    encPos = 0;
                    while (encCount-- > 0)
                    {
                        dec[decPos] = dec[encPos];
                        decPos++;
                        encPos++;
                    }
                }
            }
        } while (cmpPos < cmp.Length && decPos < dec.Length);

        return decPos;
    }

    protected virtual (int encCount, int litCount) GetLiteralToken(ReadOnlySpan<byte> cmp, ref int cmpPos) =>
        ((cmp[cmpPos] >> 0) & 0xf, (cmp[cmpPos++] >> 4) & 0xf);

    protected virtual int GetChunkEnd(ReadOnlySpan<byte> cmp, ref int cmpPos) => cmp[cmpPos++] << 0 | cmp[cmpPos++] << 8;

    protected virtual int GetLength(int length, ReadOnlySpan<byte> cmp, ref int cmpPos)
    {
        byte sum;

        if (length == 0xf)
        {
            do
            {
                length += sum = cmp[cmpPos++];
            } while (sum == 0xff);
        }

        return length;
    }
}