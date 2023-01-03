import base64
from dash import Dash, html, dcc
from dash.dependencies import Input, Output, State
import dash_cytoscape as cyto
import ipaddress
import math
import packet_analyzer
from scapy.all import *
from scapy import *
from werkzeug.utils import secure_filename

# might start using DHCP and ARP to identify hosts and gateways
"""scapy_cap = PcapReader(pcapPath)
for pkt in scapy_cap:
    continue
    if pkt.haslayer(IP):
        ip1, ip2 = pkt[IP].src, pkt[IP].dst
        ip1,ip2 = ip1,ip2 if ip1 < ip2 else ip2,ip1

        interactions += (ip1, ip2)
        ips += [ip1, ip2]
    
    #print(packet.getlayer(ARP).op)
    #if pkt.haslayer(IP) and pkt[ARP].op == 2:
    #    nodes.add(pkt[ARP].hwsrc)
    #    nodes.add(pkt[ARP].hwdst)
    #    macToIp[pkt[ARP].hwsrc] = pkt[ARP].psrc
    #    macToIp[pkt[ARP].hwdst] = pkt[ARP].pdst
    #    hostToGatewayTuples.add((pkt[ARP].hwdst, pkt[ARP].hwsrc))"""

app = Dash(__name__)
desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
pcap_upload_path = os.path.join(desktop_path, 'PcapUploads')

def get_graph_element_data(pcap_path):

    try:
        info = packet_analyzer.analyze(pcap_path)
    except:
        return "Invalid capture file"
        
    entities = info["entities"]
    interactions = info["interactions"]

    #ARP_IS_AT = 2

    network = ipaddress.ip_network('192.168.0.0/16') # hardcoded subnet, need to add support later for multiple subnets

    graphData = []
    subnetSize = sum(1 for ip in entities if ipaddress.ip_address(ip) in network)
    internetSize = len(entities) - subnetSize

    # TODO: class for position generation, ASAP!
    angle_subnet, angle_internet = 0.0, 0.0

    for ip in entities:
        in_subnet = ipaddress.ip_address(ip) in network
        if in_subnet:
            angle_subnet += 360.0 / subnetSize
        else:
            angle_internet += 360.0 / internetSize
        
        radius = 200 if in_subnet else 1000
        angle = angle_subnet if in_subnet else angle_internet
        gateway_address = '192.168.1.1'
        x = 0 if ip == gateway_address else radius * math.cos(angle * (math.pi / 180.0))
        y = 0 if ip == gateway_address else radius * math.sin(angle * (math.pi / 180.0))

        classes = 'subnet-node' if ipaddress.ip_address(ip) in network else 'internet-node'
        label = entities[ip]["hostname"] if entities[ip]["hostname"] != None else ip
        graphData.append({'data': {'id': ip, 'label': label}, 'position': {'x': x, 'y': y }, 'classes': classes})

    for edge in interactions:
        subnet_host_gateway_relation = (ipaddress.ip_address(edge[0]) in network) and (ipaddress.ip_address(edge[1]) in network) and (edge[0] == '192.168.1.1')
        graphData.append({'data': {'source': edge[0], 'target': edge[1]}, 'classes': ('subnet-edge' if subnet_host_gateway_relation else 'internet-edge') })

    cytoscape_element = cyto.Cytoscape(
            id = 'network-graphs-x-cytoscape',
            elements = graphData,
            layout = {
                'name': 'preset'
            },
            style = {
                'height':'1000px',
                'width':'100%',
            },
            # TODO: generate css classes for different subnets
            stylesheet=[
                {
                    'selector': '.subnet-edge',
                    'style': {
                        'line-color': 'blue'
                    }
                },
                {
                    'selector': '.subnet-node',
                    'style': {
                        'content': 'data(label)',
                        'background-color': 'blue'
                        #'border-color': 'blue'
                    }
                },
                {
                    'selector': '.internet-edge',
                    'style': {
                        'line-color': 'orange'
                    }
                },
                {
                    'selector': '.internet-node',
                    'style': {
                        'content': 'data(label)',
                        'background-color': 'orange'
                    }
                }
            ]
        )

    # TODO: use static files
    # TODO: make pretty design
    return html.Div(
        [
            cytoscape_element
        ])

app.layout = html.Div(
        [
            html.H2("Traffic analysis:"),
            dcc.Upload(
                id='upload-data',
                children=html.Div([
                    'Drag and Drop or ',
                    html.A('Select Files')
                ]),
                style={
                    'width': '100%',
                    'height': '60px',
                    'lineHeight': '60px',
                    'borderWidth': '1px',
                    'borderStyle': 'dashed',
                    'borderRadius': '5px',
                    'textAlign': 'center',
                    'margin': '10px'
                },
                # Allow multiple files to be uploaded
                multiple=False
            ),
            html.Div(id='output-data-upload')
        ],
        style = {
            'background':'radial-gradient(#FFFFFF 25%, #BBBBBB 95%)',
            'width': '100%',
            'height': '100%'
        })

@app.callback(Output('output-data-upload', 'children'),
              [Input('upload-data', 'contents')],
              [State('upload-data', 'filename'),
               State('upload-data', 'last_modified')])
def update_output(content, name, date):
    if content is None:
        return

    if not os.path.exists(pcap_upload_path):
        os.makedirs(pcap_upload_path)

    file_path = os.path.join(pcap_upload_path, secure_filename(name))
    octet_stream = content[content.index(',')+1:] # string looks like "octet-stream;base64 ....,[BASE64_DATA]"
    binary_data = base64.b64decode(octet_stream)

    # TODO: currently files pile up and get overwritten
    with open(file_path, "wb") as fh:
        fh.write(binary_data)
    
    return get_graph_element_data(file_path)

if __name__ == "__main__":
   app.run_server(debug=True)
