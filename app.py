from flask import Flask, render_template, request, make_response, Response, jsonify
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from io import BytesIO
from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading

app = Flask(__name__)

filter_settings = {
    'block_src_ip': [],
    'block_dst_ip': [],
    'allow_only_syn': False
}

state_counts = {'SYN-SENT': 0, 'SYN-RECEIVED': 0, 'ESTABLISHED': 0, 'FIN-WAIT': 0}
total_packets = 0

def packet_handler(packet):
    global total_packets
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        tcp_flags = packet[TCP].flags
        if (filter_settings['block_src_ip'] and src_ip in filter_settings['block_src_ip']) or (filter_settings['block_dst_ip'] and dst_ip in filter_settings['block_dst_ip']):
            return
        if filter_settings['allow_only_syn'] and 'S' not in tcp_flags:
            return
        state = None
        if 'S' in tcp_flags and 'A' not in tcp_flags:
            state = 'SYN-SENT'
        elif 'S' in tcp_flags and 'A' in tcp_flags:
            state = 'SYN-RECEIVED'
        elif 'A' in tcp_flags and 'F' not in tcp_flags:
            state = 'ESTABLISHED'
        elif 'F' in tcp_flags:
            state = 'FIN-WAIT'
        if state:
            total_packets += 1
            state_counts[state] = state_counts.get(state, 0) + 1

def start_sniffer():
    try:
        sniff(prn=packet_handler, store=False)
    except Exception as e:
        print("Error in sniffer thread:", e)

def update_filter(src_ips, dst_ips, allow_only_syn):
    filter_settings['block_src_ip'] = src_ips
    filter_settings['block_dst_ip'] = dst_ips
    filter_settings['allow_only_syn'] = allow_only_syn

def create_plot():
    fig, ax = plt.subplots()
    ax.bar(state_counts.keys(), state_counts.values(), color='blue')
    ax.set_title('TCP Connection States')
    ax.set_ylabel('Number of Packets')
    canvas = FigureCanvas(fig)
    img = BytesIO()
    canvas.print_png(img)
    plt.close(fig)
    img.seek(0)
    return img

@app.route('/')
def index():
    return render_template('index.html', filter_settings=filter_settings, state_counts=state_counts, total_packets=total_packets)

@app.route('/update_filters', methods=['POST'])
def update_filters():
    src_ips = request.form.getlist('src_ip')
    dst_ips = request.form.getlist('dst_ip')
    allow_only_syn = 'only_syn' in request.form
    update_filter(src_ips, dst_ips, allow_only_syn)
    return ('', 204)

@app.route('/plot.png')
def plot_png():
    img = create_plot()
    return Response(img.getvalue(), mimetype='image/png')

if __name__ == '__main__':
    threading.Thread(target=start_sniffer, daemon=True).start()
    app.run(debug=True)
