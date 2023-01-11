

namespace WindowsPcapAnalyzer.Utils
{
    using System.Net;

    public class ZeekDnsEntity
    {
        private const int DOMAIN_COLUMN_INDEX = 9;
        private const int IP_COLUMN_INDEX = 21;

        private string _domain;

        private string _ip;

        private bool _valid;

        public ZeekDnsEntity(string zeekOutputLine)
        {
            var columns = zeekOutputLine.Split('\t');
            _domain = columns[DOMAIN_COLUMN_INDEX];
            _ip = columns[IP_COLUMN_INDEX];

            if (IPAddress.TryParse(_ip, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                _valid = true;
            }
        }

        public bool IsValid()
        {
            return _valid;
        }

        public string Domain()
        {
            return _domain;
        }

        public string Ip()
        {
            return _ip;
        }
    }
}
