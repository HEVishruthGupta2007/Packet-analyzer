#!/usr/bin/env python3
"""
CODSOFT Cyber Security Internship - Task 1
==========================================
NETWORK PACKET ANALYZER  (web edition)

A Flask web application that captures live network traffic with Scapy and
streams the decoded packets to a browser dashboard.

Author : <your name>
Repo   : CODSOFT_TASK1

HOW TO RUN
----------
  pip install -r requirements.txt
  # Windows: also install Npcap -> https://npcap.com/#download
  # Open the terminal AS ADMINISTRATOR, then:
  python app.py
  # Visit http://127.0.0.1:5000

ARCHITECTURE
------------
  Browser  --HTTP polling-->  Flask  <--callback--  Scapy AsyncSniffer
                                 |
                          shared deque + lock

Scapy sniffs on a background thread and appends decoded packets to a shared
deque. Flask serves that deque as JSON. The browser polls once a second and
redraws. A lock guards the shared state because two threads touch it.

LEGAL / ETHICAL NOTE
--------------------
Only capture traffic on a network you own or have written permission to
monitor. Unauthorised interception is illegal in most countries.
"""

import threading
from collections import Counter, deque
from datetime import datetime

# pyrefly: ignore [missing-import]
from flask import Flask, jsonify, render_template, request

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, Raw, TCP, UDP, conf
    # pyrefly: ignore [missing-import]
    from scapy.sendrecv import AsyncSniffer
except ImportError:
    raise SystemExit(
        "Scapy is not installed.\n"
        "  pip install scapy\n"
        "On Windows you also need Npcap: https://npcap.com/#download"
    )

app = Flask(__name__)

# How many packets to keep in memory. Old ones fall off the left of the deque
# automatically, so a long capture cannot exhaust RAM.
MAX_PACKETS = 3000

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}

TCP_FLAG_NAMES = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

ICMP_TYPES = {
    0: "Echo reply", 3: "Destination unreachable",
    8: "Echo request (ping)", 11: "Time exceeded",
}


# ===========================================================================
# CaptureSession: owns everything to do with one capture run.
# ===========================================================================
class CaptureSession:
    def __init__(self):
        self.lock = threading.Lock()   # two threads touch this state
        self.sniffer = None            # Scapy's AsyncSniffer, when running
        self.reset()

    def reset(self):
        self.packets = deque(maxlen=MAX_PACKETS)
        self.next_id = 1
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()
        self.services = Counter()
        self.started_at = None
        self.interface = None
        self.bpf = None
        self.error = None

    # -------------------------------------------------------------------
    # Turn one Scapy packet into a plain dict the browser can render.
    # A packet is layers nested inside each other, so we walk down them:
    # layer 3 gives addresses, layer 4 gives ports, whatever is left is data.
    # -------------------------------------------------------------------
    def dissect(self, packet):
        info = {
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip": "-", "dst_ip": "-", "protocol": "Other",
            "src_port": None, "dst_port": None, "src_service": None,
            "dst_service": None, "length": len(packet), "ttl": None,
            "flags": None, "detail": "", "payload_hex": "", "payload_len": 0,
            "summary": packet.summary(),
        }

        # --- layer 3: who is talking to whom ---------------------------
        if packet.haslayer(IP):
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst
            info["ttl"] = packet[IP].ttl
        elif packet.haslayer(IPv6):
            info["src_ip"] = packet[IPv6].src
            info["dst_ip"] = packet[IPv6].dst
            info["ttl"] = packet[IPv6].hlim
            info["protocol"] = "IPv6"
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info["protocol"] = "ARP"
            info["src_ip"] = arp.psrc
            info["dst_ip"] = arp.pdst
            info["detail"] = (f"Who has {arp.pdst}? Tell {arp.psrc}"
                              if arp.op == 1
                              else f"{arp.psrc} is at {arp.hwsrc}")
            return info

        # --- layer 4: which service, and what kind of message ----------
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["protocol"] = "TCP"
            info["src_port"], info["dst_port"] = tcp.sport, tcp.dport
            flags = str(tcp.flags)
            info["flags"] = ",".join(TCP_FLAG_NAMES.get(f, f) for f in flags)
            info["detail"] = f"{info['flags']} seq={tcp.seq}"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["protocol"] = "UDP"
            info["src_port"], info["dst_port"] = udp.sport, udp.dport
            # DNS travels over UDP/53. Showing the domain is far more useful
            # than showing "UDP 53", so we special-case it.
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                try:
                    info["protocol"] = "DNS"
                    info["detail"] = "Query: " + packet[DNS].qd.qname.decode(
                        errors="replace").rstrip(".")
                except Exception:
                    pass
        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"
            info["detail"] = ICMP_TYPES.get(packet[ICMP].type,
                                            f"Type {packet[ICMP].type}")

        info["src_service"] = WELL_KNOWN_PORTS.get(info["src_port"])
        info["dst_service"] = WELL_KNOWN_PORTS.get(info["dst_port"])

        # --- leftover bytes are the application payload ----------------
        if packet.haslayer(Raw):
            raw = bytes(packet[Raw].load)
            info["payload_len"] = len(raw)
            # Keep only the first 512 bytes; that is plenty for inspection
            # and stops one big packet bloating the JSON response.
            info["payload_hex"] = raw[:512].hex()

        return info

    # -------------------------------------------------------------------
    # Scapy calls this on the sniffer thread for every captured packet.
    # -------------------------------------------------------------------
    def on_packet(self, packet):
        info = self.dissect(packet)
        with self.lock:
            info["id"] = self.next_id
            self.next_id += 1
            self.total_packets += 1
            self.total_bytes += info["length"]
            self.protocols[info["protocol"]] += 1
            if info["src_ip"] != "-":
                self.sources[info["src_ip"]] += 1
                self.destinations[info["dst_ip"]] += 1
            if info["dst_service"]:
                self.services[info["dst_service"]] += 1
            self.packets.append(info)

    # -------------------------------------------------------------------
    def start(self, interface=None, bpf=None):
        with self.lock:
            if self.sniffer is not None:
                return False, "A capture is already running."
        self.reset()
        self.interface = interface or None
        self.bpf = bpf or None
        self.started_at = datetime.now()
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf,
                prn=self.on_packet,
                store=False,      # we keep our own decoded copies
            )
            sniffer.start()
        except Exception as exc:
            self.error = str(exc)
            return False, self._friendly_error(exc)
        with self.lock:
            self.sniffer = sniffer
        return True, "Capturing."

    def stop(self):
        with self.lock:
            sniffer, self.sniffer = self.sniffer, None
        if sniffer is None:
            return False, "Nothing is running."
        try:
            sniffer.stop()
        except Exception:
            pass              # already dead; nothing useful to do
        return True, "Capture stopped."

    @staticmethod
    def _friendly_error(exc):
        text = str(exc).lower()
        if "permission" in text or "denied" in text or "operation not" in text:
            return ("Permission denied. Close this, reopen your terminal as "
                    "Administrator (or use sudo), and run app.py again.")
        if "npcap" in text or "winpcap" in text or "libpcap" in text:
            return ("Packet driver missing. Install Npcap from npcap.com and "
                    "restart.")
        if "no such device" in text or "not found" in text:
            return "That interface does not exist. Pick another one."
        return f"Could not start capture: {exc}"

    # -------------------------------------------------------------------
    def snapshot(self, since=0, limit=400):
        """Everything the dashboard needs, in one response."""
        with self.lock:
            running = self.sniffer is not None
            # Only send packets the browser has not seen yet.
            fresh = [p for p in self.packets if p["id"] > since]
            if len(fresh) > limit:
                fresh = fresh[-limit:]
            # Payload bytes are fetched on demand, not pushed to every client.
            rows = [{k: v for k, v in p.items() if k != "payload_hex"}
                    for p in fresh]
            elapsed = ((datetime.now() - self.started_at).total_seconds()
                       if self.started_at else 0)
            return {
                "running": running,
                "interface": self.interface,
                "bpf": self.bpf,
                "elapsed": round(elapsed, 1),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "latest_id": self.next_id - 1,
                "packets": rows,
                "protocols": self.protocols.most_common(),
                "top_sources": self.sources.most_common(5),
                "top_destinations": self.destinations.most_common(5),
                "services": self.services.most_common(6),
            }

    def payload(self, packet_id):
        with self.lock:
            for p in self.packets:
                if p["id"] == packet_id:
                    return p
        return None


session = CaptureSession()


# ===========================================================================
# ROUTES
# ===========================================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def api_interfaces():
    """List capture interfaces. Names differ a lot between platforms, so we
    show the friendly description next to the name Scapy needs."""
    found = []
    try:
        for iface in conf.ifaces.values():
            name = getattr(iface, "name", None)
            if not name:
                continue
            found.append({
                "name": name,
                "description": getattr(iface, "description", "") or name,
                "ip": getattr(iface, "ip", "") or "",
            })
    except Exception:
        # pyrefly: ignore [missing-import]
        from scapy.all import get_if_list
        found = [{"name": n, "description": n, "ip": ""}
                 for n in get_if_list()]
    # Interfaces with an IP address are the ones likely to carry traffic.
    found.sort(key=lambda i: (not i["ip"], i["description"].lower()))
    return jsonify(found)


@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    ok, message = session.start(
        interface=(data.get("interface") or "").strip() or None,
        bpf=(data.get("bpf") or "").strip() or None,
    )
    return jsonify({"ok": ok, "message": message}), (200 if ok else 400)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ok, message = session.stop()
    return jsonify({"ok": ok, "message": message})


@app.route("/api/state")
def api_state():
    since = request.args.get("since", default=0, type=int)
    return jsonify(session.snapshot(since=since))


@app.route("/api/packet/<int:packet_id>")
def api_packet(packet_id):
    found = session.payload(packet_id)
    if found is None:
        return jsonify({"error": "That packet is no longer in the buffer."}), 404
    return jsonify(found)


if __name__ == "__main__":
    print("=" * 66)
    print(" Network Packet Analyzer - CodSoft Task 1")
    print(" Dashboard: http://127.0.0.1:5000")
    print(" Needs Administrator / root privileges to capture packets.")
    print("=" * 66)
    # threaded=True so API calls still answer while the sniffer runs.
    # debug=False because the reloader would start a second sniffer thread.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)