using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Text.Json;

namespace FactoryGameSniffer;

internal static class GoogleProtoDecoder
{
    private sealed record PacketDefinition(string Name, MessageParser? Parser);

    private static readonly Dictionary<int, PacketDefinition> ClientPackets = BuildPackets("CSMessageID");
    private static readonly Dictionary<int, PacketDefinition> ServerPackets = BuildPackets("SCMessageID");

    private static Dictionary<int, PacketDefinition> BuildPackets(string enumName)
    {
        FileDescriptor schema = Proto.Game164Reflection.Descriptor;
        EnumDescriptor ids = schema.EnumTypes.Single(e => e.Name == enumName);
        Dictionary<string, MessageDescriptor> messages = schema.MessageTypes.ToDictionary(m => m.Name, StringComparer.Ordinal);
        Dictionary<int, PacketDefinition> packets = new();

        foreach (EnumValueDescriptor id in ids.Values)
        {
            // cs_ping (5) -> message CS_PING
            // sc_ping (5) -> message SC_PING
            string name = id.Name.ToUpperInvariant();

            string messageName = name switch
            {
                "CS_LOGIN" => "MSG_A1",
                "SC_LOGIN" => "MSG_B1",
                _ => name
            };

            messages.TryGetValue(messageName, out MessageDescriptor? message);
            packets.TryAdd(id.Number, new PacketDefinition(name, message?.Parser));
        }

        return packets;
    }

    public static (string PacketName, string Json) Decode(int id, PacketDirection direction, byte[] data)
    {
        Dictionary<int, PacketDefinition> definitions = direction == PacketDirection.CS ? ClientPackets : ServerPackets;
        if (!definitions.TryGetValue(id, out PacketDefinition? packet))
            return (id.ToString(), Fallback(data, "Unknown packet ID in the supplied .proto"));

        if (packet.Parser is null)
            return (packet.Name, Fallback(data, $"No message type for {packet.Name} in the suppplied .proto"));

        try
        {
            IMessage message = packet.Parser.ParseFrom(data);
            return (packet.Name, JsonFormatter.Default.Format(message));
        }
        catch (InvalidProtocolBufferException e)
        {
            return (packet.Name, Fallback(data, e.Message));
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        {
            return (packet.Name, Fallback(data, e.Message));
        }
    }

    private static string Fallback(byte[] data, string error) =>
        JsonSerializer.Serialize(new { base64 = Convert.ToBase64String(data), decodeError = error });
}
