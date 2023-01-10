import base64
from dash import Dash, html, dcc
from dash.dependencies import Input, Output, State
import dash_cytoscape as cyto
import ipaddress
import json
import math
import network_positioner
import packet_analyzer
from pathlib import Path
from scapy.all import *
from scapy import *
from werkzeug.utils import secure_filename

DESKTOP_PATH = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
PCAP_UPLOAD_PATH = os.path.join(DESKTOP_PATH, 'PcapUploads')
PCAP_ANALYSIS_PATH = os.path.join(DESKTOP_PATH, 'PcapAnalysis')

# Initialize Dash
app = Dash(__name__, suppress_callback_exceptions=True)

def get_graph_element_data(info):

    entities = info["entities"]
    network = ipaddress.ip_network('192.168.0.0/16') # hardcoded subnet, need to add support later for multiple subnets

    graphData = []
    subnetSize = sum(1 for ip in entities if ipaddress.ip_address(ip) in network)
    internetSize = len(entities) - subnetSize

    # TODO: class for position generation, ASAP!
    angle_subnet, angle_internet = 0.0, 0.0

    positions = network_positioner.get_ip_display_positions(info)
    for ip in entities:
        """in_subnet = ipaddress.ip_address(ip) in network
        if in_subnet:
            angle_subnet += 360.0 / subnetSize
        else:
            angle_internet += 360.0 / internetSize
        
        radius = 200 if in_subnet else 1000
        angle = angle_subnet if in_subnet else angle_internet
        gateway_address = '192.168.1.1'
        x = 0 if ip == gateway_address else radius * math.cos(angle * (math.pi / 180.0))
        y = 0 if ip == gateway_address else radius * math.sin(angle * (math.pi / 180.0))"""

        classes = 'subnet-node' if ipaddress.ip_address(ip) in network else 'internet-node'
        label = entities[ip]["hostname"] if entities[ip]["hostname"] != None else ip
        position = positions[ip]
        graphData.append({'data': {'id': ip, 'label': label, 'info': info["entities"][ip] }, 'position': {'x': position[0], 'y': position[1] }, 'classes': classes})

    for edge in info["interactions"]:
        subnet_host_gateway_relation = (ipaddress.ip_address(edge[0]) in network) and (ipaddress.ip_address(edge[1]) in network) and (edge[0] == '192.168.1.1')
        graphData.append({'data': {'source': edge[0], 'target': edge[1]}, 'classes': ('subnet-edge' if subnet_host_gateway_relation else 'internet-edge') })

    cytoscape_element = cyto.Cytoscape(
            id = 'network-graph-cytoscape',
            elements = graphData,
            layout = {
                'name': 'preset'
            },
            style = {
                'height':'800px',
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

    return cytoscape_element

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

                multiple=False
            ),
            html.Div(
                id='output-data-upload',
                style = {
                    'height':'800px',
                    'width':'100%',
                },
            ),
            html.Div(
                id='entity-info',
                style={
                    'widht': '100%',
                    'height': '200px',
                    'backgroundColor': '#BBB'
                }
            )
        ],
        style = {
            'background':'radial-gradient(#FFFFFF 25%, #BBBBBB 95%)',
            'width': '100%',
            'height': '100%'
        })


def process_pcap(capture_file_path, analysis_path=None):
    info = packet_analyzer.PacketAnalyzer(capture_file_path).analyze()

    if analysis_path:
        with open(analysis_path , "w" ) as f:
            json.dump(info , f, indent=4)

    return info

def save_binary_to_file_and_ready_analysis(binary_data, filename):
    os.makedirs(PCAP_UPLOAD_PATH, exist_ok = True)
    os.makedirs(PCAP_ANALYSIS_PATH, exist_ok = True)
    
    filename_stem = Path(filename).stem
    time_string = datetime.utcnow().strftime('%Y%m%d%H%M%S')

    capture_file_path = os.path.join(PCAP_UPLOAD_PATH, secure_filename(f'{filename_stem}_{time_string}.{filename.split(".")[-1]}'))
    analysis_file_path = os.path.join(PCAP_ANALYSIS_PATH, secure_filename(f'{filename_stem}_{time_string}.json'))

    with open(capture_file_path, "wb") as fh:
        fh.write(binary_data)
    
    return (capture_file_path, analysis_file_path)


# Callback for file upload
@app.callback(Output('output-data-upload', 'children'),
              [Input('upload-data', 'contents')],
              [State('upload-data', 'filename'),
               State('upload-data', 'last_modified')])
def update_output(content, uploaded_file_name, date):
    if content is None:
        return

    octet_stream = content[content.index(',')+1:] # string looks like "octet-stream;base64 ....,[BASE64_DATA]"
    binary_data = base64.b64decode(octet_stream)
    
    (capture_file_path, analysis_path) = save_binary_to_file_and_ready_analysis(binary_data, uploaded_file_name)
    info = process_pcap(capture_file_path, analysis_path)
    return get_graph_element_data(info)


# Callback for clicking nodes
@app.callback(
    Output('entity-info', 'children'),
    [Input('network-graph-cytoscape', 'tapNodeData')]
)
def update_output(node_data):
    if not node_data:
        return ""
    return str(node_data["info"])


if __name__ == "__main__":
   app.run_server(debug=True)
