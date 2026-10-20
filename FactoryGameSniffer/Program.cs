using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Text;

namespace FactoryGameSniffer;

internal static class Program
{
    // For CN might need a different host/port, but for EU/US this is the main game server.
    private const string TargetHost = "beyond-euandus.gryphline.com";
    private const int TargetPort = 30000;

    public static int Main(string[] args)
    {
        // Optional CLI:
        //   --device "<hint>"
        //   --pcap "out.pcap"
        //   --log "out.log"
        //   --visualizer-prefix "http://localhost:8080/"
        //   --no-visualizer

        string? deviceHint = null;
        string pcapOut = $"dst_{TargetHost}_{TargetPort}.pcap"; // _{DateTime.Now:yyyyMMdd_HHmmss}
        string logOut = $"dst_{TargetHost}_{TargetPort}.log"; // _{DateTime.Now:yyyyMMdd_HHmmss}
        bool enableVisualizer = true;
        string visualizerPrefix = "http://localhost:8080/";

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next()
            {
                if (i + 1 >= args.Length) throw new ArgumentException($"Missing value after {a}");
                return args[++i];
            }

            switch (a)
            {
                case "--device":
                case "-d":
                    deviceHint = Next();
                    break;
                case "--pcap":
                    pcapOut = Next();
                    break;
                case "--log":
                    logOut = Next();
                    break;
                case "--no-visualizer":
                    enableVisualizer = false;
                    break;
                case "--visualizer-prefix":
                    visualizerPrefix = Next();
                    break;
                case "--help":
                case "-?":
                case "/?":
                    PrintUsage();
                    return 0;
                default:
                    throw new ArgumentException($"Unknown argument: {a}");
            }
        }

        try
        {
            // Capture by port in both directions
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                Console.Error.WriteLine("No capture devices found. Is Npcap/libpcap installed?");
                return 3;
            }

            //foreach (ILiveDevice idevice in devices)
            //{
            //	Console.WriteLine($"{idevice.Name} -> {idevice.Description}");
            //}

            ICaptureDevice device = SelectDevice(devices, deviceHint);
            Console.WriteLine($"Using device: {device.Description}");
            Console.WriteLine($"  Name: {device.Name}");

            // Capture and write files
            device.Open(DeviceModes.Promiscuous, read_timeout: 1000);
            device.Filter = $"tcp port {TargetPort}";

            using CaptureFileWriterDevice pcapWriter = new(pcapOut);
            pcapWriter.Open(device);

            using StreamWriter logWriter = new(logOut, append: false, encoding: new UTF8Encoding(false));
            logWriter.WriteLine($"Started: {DateTimeOffset.Now:O}");
            logWriter.WriteLine($"Target : {TargetHost}:{TargetPort}");
            logWriter.WriteLine($"Device : {device.Description}");
            logWriter.WriteLine($"Filter : tcp port {TargetPort}");
            logWriter.WriteLine();

            long packetCount = 0;
            long messageCount = 0;
            TcpStreamReassembler streamReassembler = new(TargetPort);
            using PacketVisualizerServer? visualizer = enableVisualizer ? new(visualizerPrefix) : null;
            visualizer?.Start();
            Action<DecodedPacket>? publishDecoded = visualizer is null ? null : visualizer.Publish;
            if (visualizer != null)
                Console.WriteLine($"Visualizer WebSocket: {visualizerPrefix.Replace("http://", "ws://")}");

            device.OnPacketArrival += (_, e) =>
            {
                try
                {
                    Packet parsed = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

                    TcpPacket tcp = parsed.Extract<TcpPacket>();
                    if (tcp is null)
                        return;

                    // Should already be filtered, but keep a sanity check for dst port
                    if ((tcp.DestinationPort != TargetPort) && (tcp.SourcePort != TargetPort))
                        return;

                    IPv4Packet ip4 = parsed.Extract<IPv4Packet>();
                    IPv6Packet ip6 = parsed.Extract<IPv6Packet>();
                    IPAddress? srcIp = ip4?.SourceAddress ?? ip6?.SourceAddress;
                    IPAddress? dstIp = ip4?.DestinationAddress ?? ip6?.DestinationAddress;

                    if (srcIp == null || dstIp == null) return;

                    string ts = e.GetPacket().Timeval.Date.ToString("O");
                    byte[] payload = tcp.PayloadData ?? Array.Empty<byte>();

                    if (payload.Length == 0)
                        return;

                    packetCount++;
                    pcapWriter.Write(e.GetPacket());

                    //string logStr = $"[{ts}] PKT#{packetCount} {srcIp}:{tcp.SourcePort} -> {dstIp}:{tcp.DestinationPort} flags={FlagsString(tcp)} seq={tcp.SequenceNumber} payload={payload.Length}";
                    //if (payload.Length > 0 || tcp.Synchronize || tcp.Finished || tcp.Reset)
                    //{
                    //	logWriter.WriteLine(logStr);
                    //	Console.WriteLine(logStr);
                    //}

                    // Process through TCP stream reassembler
                    (PacketDirection direction, IEnumerable<byte[]> messages) = streamReassembler.ProcessPacket(tcp, srcIp, dstIp);

                    foreach (byte[] message in messages)
                    {
                        messageCount++;
                        logWriter.WriteLine($"  >> Reassembled Message #{messageCount} (length={message.Length})");
                        Console.WriteLine($"  >> Reassembled Message #{messageCount} (length={message.Length})");

                        // Process the reassembled message
                        try
                        {
                            PacketProcessor.ProcessPacket(message, direction, logWriter, publishDecoded);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Message #{messageCount} ({direction}) error: {ex.Message}");
                            logWriter.WriteLine($"  !! Message #{messageCount} ({direction}) error: {ex}");
                        }

                        logWriter.WriteLine();
                    }

                    logWriter.Flush();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Packet processing error: {ex.Message}");
                }
            };

            Console.WriteLine("Capturing... Press Ctrl+C to stop.");
            Console.WriteLine($"Writing PCAP: {pcapOut}");
            Console.WriteLine($"Writing LOG : {logOut}");

            using CancellationTokenSource cts = new();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            device.StartCapture();

            while (!cts.IsCancellationRequested)
                Thread.Sleep(200);

            device.StopCapture();
            device.Close();

            logWriter.WriteLine($"Stopped: {DateTimeOffset.Now:O}");
            logWriter.WriteLine($"Packets: {packetCount}");
            logWriter.WriteLine($"Reassembled Messages: {messageCount}");
            logWriter.WriteLine($"Active Streams: {streamReassembler.StreamCount}");

            Console.WriteLine($"Done. Packets={packetCount}, Messages={messageCount}, Streams={streamReassembler.StreamCount}");
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            PrintUsage();
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 10;
        }
    }

    private static ICaptureDevice SelectDevice(CaptureDeviceList devices, string? hint)
    {
        if (!string.IsNullOrWhiteSpace(hint))
        {
            string h = hint.Trim();
            ILiveDevice? match = devices.FirstOrDefault(d =>
                (d.Name?.Contains(h, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (d.Description?.Contains(h, StringComparison.OrdinalIgnoreCase) ?? false));

            if (match != null)
                return match;

            Console.Error.WriteLine("No device matched --device hint. Available devices:");
            foreach (ILiveDevice d in devices)
                Console.Error.WriteLine($"  {d.Description} ({d.Name})");

            throw new ArgumentException("Device hint did not match any device.");
        }

        // Just for my personal convenience
        ICaptureDevice? wifiDevice = devices.FirstOrDefault(i =>
            i.Description?.Contains("Realtek PCIe 2.5GbE Family Controller", StringComparison.OrdinalIgnoreCase) == true);
        if (wifiDevice != null)
            return wifiDevice;

        // Default: first device
        return devices[0];
    }

    private static void PrintUsage()
    {
        Console.WriteLine($@"FactoryGameSniffer - capture and decode TCP game packets on port {TargetPort}

Usage:
  FactoryGameSniffer [--device <hint>] [--pcap <file>] [--log <file>]
                  [--no-visualizer] [--visualizer-prefix <http-prefix>]

The Packet-Visualizer frontend connects to ws://localhost:8080 by default.
Example:
  dotnet run -- --device Ethernet
  dotnet run -- --visualizer-prefix http://localhost:8080/
");
    }
}
