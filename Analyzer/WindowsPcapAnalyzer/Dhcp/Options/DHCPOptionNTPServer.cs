﻿/// The MIT License(MIT)
/// 
/// Copyright(c) 2017 Conscia Norway AS
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

using Dhcp.Enums;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Dhcp.Options
{
    public class DHCPOptionNTPServer : DHCPOption
    {
        // TODO : Deep copy
        public List<IPAddress> NTPServers { get; set; } = new List<IPAddress>();

        public DHCPOptionNTPServer(List<IPAddress> ntpServers)
        {
            NTPServers = ntpServers;
        }

        public DHCPOptionNTPServer(int optionLength, byte[] buffer, long offset)
        {
            NTPServers = ReadIPAddresses(buffer, offset, optionLength);
        }

        public override string ToString()
        {
            return "NTP servers : " + string.Join(",", NTPServers.Select(x => x.ToString()).ToArray());
        }

        public override Task Serialize(Stream stream)
        {
            return SerializeIPAddressList(stream, DHCPOptionType.NTPServers, NTPServers);
        }
    }
}
