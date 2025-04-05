
from flask import Flask, render_template_string, request, send_file
import socket
import time
from fpdf import FPDF
import os

app = Flask(__name__)
results_global = []

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SMB Scanner</title>
    <style>
        body { font-family: Arial; background: #f0f0f0; padding: 20px; }
        table { width: 100%; background: white; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #ccc; text-align: center; }
        th { background: #444; color: white; }
    </style>
</head>
<body>
    <h1>SMB Auto Exploit Scanner</h1>
    <form method="POST">
        <textarea name="ips" rows="10" style="width:100%;" placeholder="Enter IPs (one per line)"></textarea><br><br>
        <button type="submit">Start Scan</button>
    </form>

    {% if results %}
    <h2>Scan Results:</h2>
    <table>
        <tr><th>IP</th><th>Port 445</th><th>NTLM Detected</th><th>Exploited</th></tr>
        {% for r in results %}
        <tr>
            <td>{{ r.ip }}</td>
            <td style="color: {{ 'green' if r.open else 'red' }}">{{ 'Open' if r.open else 'Closed' }}</td>
            <td style="color: {{ 'green' if r.ntlm else 'red' }}">{{ 'Yes' if r.ntlm else 'No' }}</td>
            <td style="color: {{ 'green' if r.exploited else 'red' }}">{{ 'Yes' if r.exploited else 'No' }}</td>
        </tr>
        {% endfor %}
    </table>
    <br>
    <a href="/download" target="_blank">
        <button>Download PDF Report</button>
    </a>
    {% endif %}
</body>
</html>
'''

def check_smb_port(ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, 445))
        s.close()
        return True
    except:
        return False

def send_ntlm_request(ip):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, 445))
        negotiate = (
            b"\x00\x00\x00\x85" +
            b"\xff\x53\x4d\x42" +
            b"\x72\x00\x00\x00\x00\x18\x53\xc8" +
            b"\x00\x26" + b"\x00" * 6 +
            b"\x00" * 8 + b"\x00" * 16 +
            b"\x00\x00" * 4 + b"\x00" * 4 +
            b"\x00\x31" + b"\x00" * 49
        )
        s.send(negotiate)
        data = s.recv(1024)
        s.close()
        return b"NTLMSSP" in data
    except:
        return False

def simulate_exploit(ip):
    time.sleep(1)
    return "NT AUTHORITY\\SYSTEM"

def scan_ip(ip):
    result = {"ip": ip, "open": False, "ntlm": False, "exploited": False, "output": ""}
    if check_smb_port(ip):
        result["open"] = True
        if send_ntlm_request(ip):
            result["ntlm"] = True
            result["output"] = simulate_exploit(ip)
            result["exploited"] = True
    return result

def scan_ip_list(ip_list):
    results = []
    for ip in ip_list:
        res = scan_ip(ip.strip())
        results.append(res)
    return results

def export_to_pdf(results, filename="report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="SMB Exploit Report", ln=True, align='C')
    pdf.ln(10)
    for r in results:
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 8, txt=f"IP: {r['ip']}", ln=True)
        pdf.cell(200, 8, txt=f" - Port 445: {'Open' if r['open'] else 'Closed'}", ln=True)
        pdf.cell(200, 8, txt=f" - NTLM Challenge: {'Yes' if r['ntlm'] else 'No'}", ln=True)
        pdf.cell(200, 8, txt=f" - Exploited: {'Yes' if r['exploited'] else 'No'}", ln=True)
        if r["exploited"]:
            pdf.cell(200, 8, txt=f" - Output: {r['output']}", ln=True)
        pdf.ln(5)
    pdf.output(filename)

@app.route("/", methods=["GET", "POST"])
def index():
    global results_global
    results = []
    if request.method == "POST":
        raw_ips = request.form["ips"]
        ip_list = raw_ips.strip().splitlines()
        results = scan_ip_list(ip_list)
        results_global = results
        export_to_pdf(results, "report.pdf")
    return render_template_string(HTML_TEMPLATE, results=results)

@app.route("/download")
def download():
    if os.path.exists("report.pdf"):
        return send_file("report.pdf", as_attachment=True)
    return "Report not found", 404

def show_banner():
    banner = r'''
  _  __           _           _   _ _     
 | |/ /___ _   _ | | __ _  __| | | (_)___ 
 | ' // _ \ | | || |/ _` |/ _` | | | / __|
 | . \  __/ |_| || | (_| | (_| | | | \__ \
 |_|\_\___|\__, ||_|\__,_|\__,_| |_|_|___/
           |___/      SMB Scanner v1.0
                by kader11000
    '''
    print(banner)

if __name__ == "__main__":
    show_banner()
    app.run(host="0.0.0.0", port=8080)
