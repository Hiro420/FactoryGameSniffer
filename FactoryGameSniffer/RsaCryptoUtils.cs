using System.Security.Cryptography;

public static class RsaCryptoUtils
{
    public static RSA CreateRsaFromPkcs1Base64(string privateKeyBase64)
    {
        if (privateKeyBase64 == null)
            throw new ArgumentNullException(nameof(privateKeyBase64));

        // .NET's base64 decoder tolerates whitespace/newlines
        byte[] der = Convert.FromBase64String(privateKeyBase64);

        using MemoryStream ms = new(der, writable: false);
        using BinaryReader br = new(ms);

        // Expect ASN.1 SEQUENCE (0x30) with length in short/long form (0x81/0x82)
        ReadAsn1SequenceHeader(br);

        // Expect version INTEGER 0
        ReadAsn1VersionZero(br);

        // Read PKCS#1 integers in order:
        // modulus (n), publicExponent (e), privateExponent (d),
        // prime1 (p), prime2 (q), exponent1 (dp), exponent2 (dq), coefficient (iq)
        byte[] n = ReadAsn1Integer(br);
        byte[] e = ReadAsn1Integer(br);
        byte[] d = ReadAsn1Integer(br);
        byte[] p = ReadAsn1Integer(br);
        byte[] q = ReadAsn1Integer(br);
        byte[] dp = ReadAsn1Integer(br);
        byte[] dq = ReadAsn1Integer(br);
        byte[] iq = ReadAsn1Integer(br);

        RSAParameters rsaParams = new()
        {
            Modulus = n,
            Exponent = e,
            D = d,
            P = p,
            Q = q,
            DP = dp,
            DQ = dq,
            InverseQ = iq
        };

        RSA rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        return rsa;
    }

    private static void ReadAsn1SequenceHeader(BinaryReader br)
    {
        byte tag = br.ReadByte();
        if (tag != 0x30) // SEQUENCE
            throw new CryptographicException($"Unexpected ASN.1 tag 0x{tag:X2}, expected SEQUENCE (0x30).");

        int length = ReadAsn1Length(br);
        if (length < 0 || length > br.BaseStream.Length - br.BaseStream.Position)
            throw new CryptographicException("Invalid ASN.1 SEQUENCE length.");
    }

    private static void ReadAsn1VersionZero(BinaryReader br)
    {
        byte tag = br.ReadByte();
        if (tag != 0x02) // INTEGER
            throw new CryptographicException($"Unexpected ASN.1 tag 0x{tag:X2}, expected INTEGER (0x02) for version.");

        int len = ReadAsn1Length(br);
        if (len != 1)
            throw new CryptographicException("Unexpected version length in RSAPrivateKey.");

        byte version = br.ReadByte();
        if (version != 0x00)
            throw new CryptographicException($"Unexpected RSAPrivateKey version {version} (expected 0).");
    }

    private static byte[] ReadAsn1Integer(BinaryReader br)
    {
        byte tag = br.ReadByte();
        if (tag != 0x02)
            throw new CryptographicException($"Unexpected ASN.1 tag 0x{tag:X2}, expected INTEGER (0x02).");

        int len = ReadAsn1Length(br);
        if (len <= 0)
            throw new CryptographicException("Invalid INTEGER length.");

        byte[] bytes = br.ReadBytes(len);
        if (bytes.Length != len)
            throw new EndOfStreamException("Truncated ASN.1 INTEGER.");

        if (bytes.Length > 1 && bytes[0] == 0x00)
        {
            byte[] trimmed = new byte[bytes.Length - 1];
            Buffer.BlockCopy(bytes, 1, trimmed, 0, trimmed.Length);
            bytes = trimmed;
        }

        return bytes;
    }

    private static int ReadAsn1Length(BinaryReader br)
    {
        byte b = br.ReadByte();

        if ((b & 0x80) == 0) // short form
            return b;

        int numBytes = b & 0x7F;
        if (numBytes == 0 || numBytes > 4)
            throw new CryptographicException("Invalid ASN.1 length encoding.");

        int length = 0;
        for (int i = 0; i < numBytes; i++)
        {
            length = (length << 8) | br.ReadByte();
        }
        return length;
    }
}
