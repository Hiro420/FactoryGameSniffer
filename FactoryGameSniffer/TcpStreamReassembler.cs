using PacketDotNet;
using System.Net;

namespace FactoryGameSniffer;

public class TcpStreamReassembler
{
    private class TcpStream
    {
        public uint InitialSeq { get; set; }
        public uint NextExpectedSeq { get; set; }
        public SortedDictionary<uint, byte[]> BufferedSegments { get; } = new();
        public List<byte> ReassembledData { get; } = new();
        public bool Initialized { get; set; }
    }

    private class StreamKey
    {
        public IPAddress SourceIp { get; }
        public int SourcePort { get; }
        public IPAddress DestinationIp { get; }
        public int DestinationPort { get; }

        public StreamKey(IPAddress srcIp, int srcPort, IPAddress dstIp, int dstPort)
        {
            SourceIp = srcIp;
            SourcePort = srcPort;
            DestinationIp = dstIp;
            DestinationPort = dstPort;
        }

        public override bool Equals(object? obj)
        {
            if (obj is not StreamKey other) return false;
            return SourceIp.Equals(other.SourceIp) &&
                   SourcePort == other.SourcePort &&
                   DestinationIp.Equals(other.DestinationIp) &&
                   DestinationPort == other.DestinationPort;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(SourceIp, SourcePort, DestinationIp, DestinationPort);
        }

        public override string ToString()
        {
            return $"{SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort}";
        }
    }

    private readonly Dictionary<StreamKey, TcpStream> _streams = new();
    private readonly int _targetPort;

    public TcpStreamReassembler(int targetPort)
    {
        _targetPort = targetPort;
    }

    public (PacketDirection direction, IEnumerable<byte[]> messages) ProcessPacket(TcpPacket tcp, IPAddress srcIp, IPAddress dstIp)
    {
        PacketDirection direction = (tcp.DestinationPort == _targetPort) ? PacketDirection.CS : PacketDirection.SC;

        var key = new StreamKey(srcIp, tcp.SourcePort, dstIp, tcp.DestinationPort);

        if (!_streams.TryGetValue(key, out var stream))
        {
            stream = new TcpStream();
            _streams[key] = stream;
        }

        var payload = tcp.PayloadData ?? Array.Empty<byte>();

        // Handle SYN packet (initialize stream)
        if (tcp.Synchronize)
        {
            stream.InitialSeq = tcp.SequenceNumber;
            stream.NextExpectedSeq = tcp.SequenceNumber + 1;
            stream.Initialized = true;
            return (direction, Enumerable.Empty<byte[]>()); // No data in SYN
        }

        // Skip packets without payload
        if (payload.Length == 0)
        {
            return (direction, Enumerable.Empty<byte[]>());
        }

        // Handle FIN/RST (cleanup stream)
        if (tcp.Finished || tcp.Reset)
        {
            // Flush any remaining buffered data before cleanup
            var flushedMessages = FlushStream(stream).ToList();
            _streams.Remove(key);
            return (direction, flushedMessages);
        }

        // If stream not initialized yet, initialize with current seq
        if (!stream.Initialized)
        {
            stream.InitialSeq = tcp.SequenceNumber;
            stream.NextExpectedSeq = tcp.SequenceNumber;
            stream.Initialized = true;
        }

        uint currentSeq = tcp.SequenceNumber;

        // Check if this is the expected sequence number
        if (currentSeq == stream.NextExpectedSeq)
        {
            // Add payload to reassembled data
            stream.ReassembledData.AddRange(payload);
            stream.NextExpectedSeq = currentSeq + (uint)payload.Length;

            // Check if we have buffered segments that can now be processed
            while (stream.BufferedSegments.Count > 0)
            {
                var firstBuffered = stream.BufferedSegments.First();
                if (firstBuffered.Key == stream.NextExpectedSeq)
                {
                    stream.ReassembledData.AddRange(firstBuffered.Value);
                    stream.NextExpectedSeq += (uint)firstBuffered.Value.Length;
                    stream.BufferedSegments.Remove(firstBuffered.Key);
                }
                else
                {
                    break;
                }
            }

            // Try to extract complete messages
            return (direction, ExtractCompleteMessages(stream).ToList());
        }
        else if (IsSequenceAfter(currentSeq, stream.NextExpectedSeq))
        {
            // Out-of-order packet - buffer it
            if (!stream.BufferedSegments.ContainsKey(currentSeq))
            {
                stream.BufferedSegments[currentSeq] = payload;
            }
        }
        // else: retransmission or old packet - ignore

        return (direction, Enumerable.Empty<byte[]>());
    }

    private IEnumerable<byte[]> ExtractCompleteMessages(TcpStream stream)
    {
        while (stream.ReassembledData.Count >= 3)
        {
            // Frame: 1 byte header length + 2-byte UNSIGNED LE body length.
            // A signed short broke valid frames with bodies larger than 32767 bytes,
            // permanently desynchronizing the encrypted stream.
            byte headLen = stream.ReassembledData[0];
            ushort bodyLen = (ushort)(stream.ReassembledData[1] | (stream.ReassembledData[2] << 8));

            if (headLen == 0 || headLen > 200)
            {
                // Invalid header - possibly corrupted data
                // Skip one byte and try again
                stream.ReassembledData.RemoveAt(0);
                continue;
            }

            int totalLen = 3 + headLen + bodyLen;

            // Check if we have the complete message
            if (stream.ReassembledData.Count >= totalLen)
            {
                byte[] message = stream.ReassembledData.GetRange(0, totalLen).ToArray();
                stream.ReassembledData.RemoveRange(0, totalLen);
                yield return message;
            }
            else
            {
                // Wait for more data
                break;
            }
        }
    }

    private IEnumerable<byte[]> FlushStream(TcpStream stream)
    {
        // Process any remaining buffered segments
        foreach (var segment in stream.BufferedSegments.OrderBy(kv => kv.Key))
        {
            stream.ReassembledData.AddRange(segment.Value);
        }
        stream.BufferedSegments.Clear();

        // Extract any complete messages
        foreach (var message in ExtractCompleteMessages(stream))
        {
            yield return message;
        }
    }

    private bool IsSequenceAfter(uint seq1, uint seq2)
    {
        // Handle sequence number wraparound
        return unchecked((int)(seq1 - seq2)) > 0;
    }

    public void ClearStream(IPAddress srcIp, int srcPort, IPAddress dstIp, int dstPort)
    {
        var key = new StreamKey(srcIp, srcPort, dstIp, dstPort);
        _streams.Remove(key);
    }

    public int StreamCount => _streams.Count;
}
