



namespace WindowsPcapAnalyzer.Utils
{
    using Dhcp;
    using Dhcp.Options;
    using PcapDotNet.Packets;
    using PcapDotNet.Packets.Dns;
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public static class PacketUtils
    {
        public static bool TryGetLocalHostnames(this Packet packet, Dictionary<string, string> entities)
        {
            entities ??= new ();
            bool result = false;
            var dns = packet?.Ethernet?.IpV4?.Udp?.Dns;
            const int maxAnswerCount = 16;

            try
            {
                // AnswerCount can be wrong or really large, wrap in try-catch
                // and limit to maxAnswerCount to avoid too much exceptions (performance issues)
                if ((dns?.AnswerCount ?? 0) == 0 || (dns?.AnswerCount ?? int.MaxValue) > maxAnswerCount)
                {
                    return false;
                }

                for (int i = 0; i < dns.AnswerCount; i++)
                {
                    var answer = dns.Answers[i];

                    if (answer.Data is not DnsResourceDataIpV4 ipV4)
                    {
                        continue;
                    }

                    var domain = answer.DomainName.ToString();
                    if (domain.EndsWith("."))
                    {
                        domain = domain.Substring(0, domain.Length - 1);
                    }

                    if (!domain.EndsWith(".local"))
                    {
                        continue;
                    }

                    domain = domain.Substring(0, domain.IndexOf(".local"));
                    if (!entities.TryGetValue(domain, out _))
                    {
                        var ip = ipV4.Data.ToString();
                        entities[domain] = ip;
                        result = true;
                    }
                }
            }
            catch
            {
                return false;
            }

            return result;
        }

        public static bool TryGetGateway(this Packet packet, out string ip)
        {
            ip = null;

            try
            {
                var udp = packet?.Ethernet?.IpV4?.Udp;
                if (udp == null || !udp.IsValid)
                {
                    return false;
                }

                var dhcp = DHCPPacketParser.Parse(udp.Payload?.ToMemoryStream()?.ToArray());
                if (dhcp == null)
                {
                    return false;
                }

                if (!dhcp.options.Any(x => x is DHCPOptionDHCPMessageType type && type.MessageType == Dhcp.Enums.DHCPMessageType.DHCPACK))
                {
                    return false;
                }

                var mask = ((DHCPOptionSubnetMask)dhcp.options.FirstOrDefault(x => x is DHCPOptionSubnetMask mask))?.SubnetMask;
                var gatewayAddress = ((DHCPOptionDHCPServerIdentifier)dhcp.options.FirstOrDefault(x => x is DHCPOptionDHCPServerIdentifier mask))?.ServerIdentifier;
                //Console.WriteLine($"Gateway: {gatewayAddress}, Mask: {mask}");
                ip = gatewayAddress.ToString();
                return true;
            }
            catch
            {

            }

            //var arp = packet?.Ethernet; // IsValid ?? false ? packet?.Ethernet?.Arp.SenderProtocolIpV4Address;
            //if (arp?.IsValid ?? false && arp.Operation == ArpOperation.Request)
            //{
            //    ip = arp.SenderProtocolIpV4Address.ToString();
            //}

            return false; //ip != null;
        }
    }
}
