using Newtonsoft.Json;
using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Channels;

namespace FactoryGameSniffer;

internal sealed class PacketVisualizerServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly Channel<string> _packets = Channel.CreateBounded<string>(new BoundedChannelOptions(2048)
    {
        SingleReader = true,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private readonly HashSet<WebSocket> _clients = new();
    private readonly object _gate = new();
    private bool _started;

    public PacketVisualizerServer(string listenPrefix = "http://localhost:8080/")
    {
        _listener.Prefixes.Add(listenPrefix);
    }

    public void Start()
    {
        _listener.Start();
        _started = true;
        _ = Task.Run(AcceptClientsAsync);
        _ = Task.Run(BroadcastPacketsAsync);
    }

    public void Publish(DecodedPacket packet)
    {
        if (!_started || _shutdown.IsCancellationRequested)
            return;

        string message = JsonConvert.SerializeObject(new
        {
            packetId = 1,
            data = new
            {
                time = _uptime.ElapsedMilliseconds,
                source = packet.Direction == PacketDirection.CS ? "client" : "server",
                packetId = packet.PacketId,
                packetName = packet.PacketName,
                length = packet.Length,
                data = packet.JsonData
            }
        });
        _packets.Writer.TryWrite(message);
    }

    private async Task AcceptClientsAsync()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException || _shutdown.IsCancellationRequested)
            {
                break;
            }

            try
            {
                if (!context.Request.IsWebSocketRequest)
                {
                    context.Response.StatusCode = 400;
                    context.Response.Close();
                    continue;
                }

                var accepted = await context.AcceptWebSocketAsync(subProtocol: null);
                var client = accepted.WebSocket;

                await SendTextAsync(client, JsonConvert.SerializeObject(new
                {
                    packetId = 0,
                    data = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                }), _shutdown.Token);

                lock (_gate) _clients.Add(client);
                _ = Task.Run(() => ReceiveClientAsync(client));
                Console.WriteLine("Packet-Visualizer connected.");
            }
            catch (Exception ex) when (ex is WebSocketException or HttpListenerException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
                if (!_shutdown.IsCancellationRequested)
                    Console.Error.WriteLine($"Visualizer connection failed: {ex.Message}");
            }
        }
    }

    private async Task ReceiveClientAsync(WebSocket client)
    {
        try
        {
            var buffer = new byte[1024];
            while (!_shutdown.IsCancellationRequested && client.State == WebSocketState.Open)
            {
                var result = await client.ReceiveAsync(new ArraySegment<byte>(buffer), _shutdown.Token);
                if (result.MessageType == WebSocketMessageType.Close)
                    break;
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or InvalidOperationException) { }
        finally { RemoveClient(client); }
    }

    private async Task BroadcastPacketsAsync()
    {
        try
        {
            await foreach (var message in _packets.Reader.ReadAllAsync(_shutdown.Token))
            {
                WebSocket[] clients;
                lock (_gate) clients = _clients.ToArray();

                foreach (var client in clients)
                {
                    try
                    {
                        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
                        timeout.CancelAfter(TimeSpan.FromSeconds(2));
                        await SendTextAsync(client, message, timeout.Token);
                    }
                    catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
                    {
                        RemoveClient(client);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private static Task SendTextAsync(WebSocket client, string message, CancellationToken token)
    {
        var bytes = Encoding.UTF8.GetBytes(message);
        return client.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, endOfMessage: true, cancellationToken: token);
    }

    private void RemoveClient(WebSocket client)
    {
        lock (_gate) _clients.Remove(client);
        client.Dispose();
    }

    public void Dispose()
    {
        if (!_started) return;
        _started = false;
        _shutdown.Cancel();
        _packets.Writer.TryComplete();
        _listener.Stop();
        _listener.Close();
        lock (_gate)
        {
            foreach (var client in _clients) client.Dispose();
            _clients.Clear();
        }
    }
}
