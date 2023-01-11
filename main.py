import base64
from dash import Dash, html, dcc
from dash.dependencies import Input, Output, State
import dash_cytoscape as cyto
import ipaddress
import json
import math
import network_positioner
import network_colorizer
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

    graphData = []
    node_positions = network_positioner.get_ip_display_positions(info)
    subnet_colors = network_colorizer.get_subnet_node_colors(info)
    for ip in entities:
        node_class = f'subnet-node{int(ipaddress.ip_network(entities[ip]["subnet"]).network_address)}'
        label = entities[ip]["hostname"] if entities[ip]["hostname"] != None else ip
        position = node_positions[str(ip)]
        graphData.append({'data': {'id': ip, 'label': label, 'info': entities[ip] }, 'position': {'x': position[0], 'y': position[1] }, 'classes': node_class})

    for edge in info["interactions"]:
        graphData.append({'data': {'source': edge[0], 'target': edge[1]}, 'classes': 'edge' })

    cyto_stylesheet = [{
                    'selector': '.edge',
                    'style': {
                        'line-color': '#555'
                    }
                }]
    
    for subnet in subnet_colors:
        cyto_stylesheet.append({
                        'selector': f'.subnet-node{int(ipaddress.ip_network(subnet).network_address)}',
                        'style': {
                            'content': 'data(label)',
                            'background-color': f'#{subnet_colors[subnet]}'
                        }
                    })

    cytoscape_element = cyto.Cytoscape(
            id = 'network-graph-cytoscape',
            elements = graphData,
            layout = {
                'name': 'preset'
            },
            style = {
                'height':'800px',
                'width':'100%'
            },

            stylesheet = cyto_stylesheet
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

process_pcap("C:\\Users\\Carlos\\Desktop\\Carlos Kassis\\PCAPs\\bigFlows.pcap")

if __name__ == "__main__":
   app.run_server(debug=True)
