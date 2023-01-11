using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using WindowsPcapAnalyzer.Utils;
using System.Threading;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;

namespace WindowsPcapAnalyzer
{
    internal class Program
    {
        private static readonly ConcurrentDictionary<string, string> _hosts = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentBag<string> _gateways = new ConcurrentBag<string>();
        private static readonly ConcurrentBag<(string, string)> _interactions = new ConcurrentBag<(string, string)>();
        private static readonly List<Packet> _packets = new List<Packet>();
        private static int _packetsProcessed;

        static async Task Main(string[] args)
        {
            string filePath = @".\bigFlows.pcap";
            OfflinePacketDevice selectedDevice = new OfflinePacketDevice(filePath);

            Console.WriteLine($"Analysing capture file: {filePath}");

            DateTime fileReadStartTime = DateTime.Now;

            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // Portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // Promiscuous mode
                                    1000))                                  // Read timeout
            {
                // Read until EOF
                communicator.ReceivePackets(0, OnPacketReceive);
            }

            Console.WriteLine($"Finished reading capture file. Read time: {DateTime.Now - fileReadStartTime}[sec]");

            new Thread(() =>
            {
                while (true)
                {
                    Console.WriteLine($"Processed packets: {_packetsProcessed}/{_packets.Count}");
                    if (_packetsProcessed == _packets.Count)
                        break;

                    Thread.Sleep(500);
                }
            }).Start();

            DateTime sniffStartTime = DateTime.Now;

            const int threadCount = 8;
            var packets = _packets.ToArray();
            int chunkSize = packets.Length / threadCount + 1;
            await Task.WhenAll(Enumerable.Range(0, threadCount).Select(i =>
            {
                return Task.Run(() => ProcessPackets(packets, i * chunkSize, chunkSize));
            }));

            Console.WriteLine($"Finished analyzing capture file. Process time: {DateTime.Now - sniffStartTime}[sec]");

            Console.WriteLine(Environment.NewLine + "Press any key to exit...");
            Console.ReadKey();
        }

        private static void ProcessPackets(Packet[] packets, int start, int count)
        {
            int end = start + count;
            for (int i = start; i < end; i++)
            {
                if (i >= packets.Length)
                {
                    break;
                }

                Packet packet = packets[i];
                var sourceIp = packet?.IpV4?.Source.ToString();
                var destIp = packet?.IpV4?.Destination.ToString();

                if (destIp == null || sourceIp == null)
                {
                    continue;
                }

                var leftIp = sourceIp.CompareTo(destIp) < 0 ? sourceIp : destIp;
                var rightIp = sourceIp.CompareTo(destIp) >= 0 ? sourceIp : destIp;

                _interactions.Add((leftIp, rightIp));

                if (packet.TryGetGateway(out string gatewayIp))
                {
                    _gateways.Add(null);
                }

                Interlocked.Increment(ref _packetsProcessed);
            }
        }

        private static void OnPacketReceive(Packet packet)
        {
            _packets.Add(packet);
        }
    }
}