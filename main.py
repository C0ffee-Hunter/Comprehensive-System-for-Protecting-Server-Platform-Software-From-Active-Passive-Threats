#!/usr/bin/python3

import logging
import subprocess
import requests
import os
import traceback
from scapy.all import sniff, IP, TCP
from scapy.layers.inet import IP, TCP
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)  # Создание экземпляра приложения Flask


class NetworkSecurityMonitor:
    def __init__(self, data_path, report_path):
        self.data_path = data_path
        self.report_path = report_path
        self.api_key = os.getenv('IPDATA_API_KEY', 'default_key')
        self.ip_syn_count = defaultdict(int)  # Счетчик SYN-запросов для каждого IP
        self.ip_block_time = defaultdict(lambda: datetime.min)  # Время последнего блокирования IP
        self.traffic_data = []
        self.port_scan_count = defaultdict(int)
        self.sniffer_active = False
        self.captured_packets = []  # Хранение захваченных пакетов
        self.setup_logging()
        self.setup_firewall()

    def setup_logging(self):
        logging.basicConfig(filename='network_security.log', level=logging.DEBUG,
                            format='%(asctime)s:%(levelname)s:%(message)s')
        logging.debug("Logging setup complete.")

    def setup_firewall(self):
        subprocess.run("iptables -F", shell=True)  # Очистка текущих правил
        self.update_firewall_rules_initial()

    def update_firewall_rules_initial(self):
        rules = [
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT"
        ]
        for rule in rules:
            subprocess.run(rule, shell=True)
        logging.debug("Initial firewall rules set.")

    def run_sniffer(self):
        if not self.sniffer_active:
            self.sniffer_active = True
            print("Starting the sniffer on eth0...")
            logging.info("Starting the sniffer on eth0...")
            try:
                sniff(filter="tcp", prn=self.analyze_packet, store=False, iface='eth0', timeout=60)
            except Exception as e:
                print(f"Error occurred while sniffing: {e}")
                logging.error(f"Error occurred while sniffing: {e}")
            print("Sniffer stopped")
            logging.info("Sniffer stopped")
            self.sniffer_active = False
        else:
            print("Sniffer is already running.")

    def stop_sniffer(self):
        self.sniffer_active = False
        print("Sniffer stopped")
        logging.info("Sniffer stopped")

    def update_firewall(self, ip_address, action='block'):
        """
        Обновляет правила фаервола, добавляя или удаляя правила блокировки для заданных IP-адресов.
        :param ip_address: IP-адрес для блокировки или разблокировки.
        :param action: Действие 'block' или 'unblock'.
        """
        if action == 'block':
            rule = "iptables -A INPUT -s {0} -j DROP".format(ip_address)
        else:
            rule = "iptables -D INPUT -s {0} -j DROP".format(ip_address)
        try:
            subprocess.run(rule, shell=True, check=True)
            self.ip_block_time[ip_address] = datetime.now() if action == 'block' else datetime.min
            action_message = 'added' if action == 'block' else 'removed'
            logging.info("Firewall rule {0}: {1}".format(action_message, rule))
        except subprocess.CalledProcessError as e:
            logging.error("Failed to {0} IP {1} in firewall: {2}".format(action, ip_address, str(e)))

    def analyze_packet(self, packet):
        # logging.debug("Analyzing packet: %s", packet.summary())

        if packet.haslayer(TCP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            tcp_flags = packet[TCP].flags

            logging.debug("Analyzing packet: IP src {0}, IP dst {1}, TCP sport {2}, TCP dport {3}".format(
                packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport))
            self.count_syn_packets(packet[IP].src)
            self.detect_ip_spoofing(ip_src, ip_dst)
            self.detect_ddos_attack(ip_src)
            self.detect_session_hijacking(ip_src, tcp_flags)
            self.detect_port_scanning(ip_src, tcp_dport)
            if self.detect_syn_flood(packet[IP].src):
                self.block_ip(packet[IP].src)
        logging.debug("Packet analysis complete. SYN count for {0}: {1}".format(ip_src, self.ip_syn_count[ip_src]))
        logging.info("Traffic captured: {0} to {1}".format(ip_src, ip_dst))

        self.traffic_data.append({
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "tcp_sport": tcp_sport,
            "tcp_dport": tcp_dport,
            "timestamp": datetime.now().isoformat()
        })

    def count_syn_packets(self, src_ip):
        current_time = datetime.now()
        self.ip_syn_count[src_ip] += 1
        logging.debug("SYN count for {0}: {1}".format(src_ip, self.ip_syn_count[src_ip]))
        if current_time - self.ip_block_time[src_ip] > timedelta(minutes=5):
            self.ip_syn_count[src_ip] = 0
            self.ip_block_time[src_ip] = current_time

    def detect_syn_flood(self, src_ip):
        threshold = 100
        if self.ip_syn_count[src_ip] > threshold:
            logging.warning("Detected SYN flood from {0}. Count: {1}".format(src_ip, self.ip_syn_count[src_ip]))
            return True
        logging.info("No SYN flood detected for IP {0}. Count: {1}".format(src_ip, self.ip_syn_count[src_ip]))
        return False

    def monitor_traffic(self, packet):
        if packet.haslayer(IP):
            logging.info("Traffic captured: {} to {}".format(packet[IP].src, packet[IP].dst))
            self.check_ip_reputation(packet[IP].src)  # Проверка репутации IP

    # Проверка репутации IP через внешний API
    def check_ip_reputation(self, ip_address):
        response = requests.get("https://api.ipdata.co/{}?api-key={}".format(ip_address, self.api_key))
        if response.status_code == 200:
            data = response.json()
            if data.get('threat', {}).get('is_threat', False):
                logging.warning("Malicious IP detected: {}".format(ip_address))
            else:
                logging.info("IP {} is safe.".format(ip_address))
        else:
            logging.error("Failed to fetch reputation for IP {}".format(ip_address))

    def get_traffic_data(self):
        # Возвращает данные о захваченном трафике
        return self.captured_packets

    def generate_report(self):
        report = {
            "total_packets": len(self.captured_packets),
            "suspicious_ips": [ip for ip, count in self.ip_syn_count.items() if count > 0],
            "blocked_ips": list(self.ip_block_time.keys())
        }
        return report

    def detect_ip_spoofing(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport

            logging.info(
                "Analyzing packet: IP src {}, IP dst {}, TCP sport {}, TCP dport {}".format(ip_src, ip_dst, tcp_sport,
                                                                                            tcp_dport))

            # Проверка на спуфинг
            if ip_src == ip_dst:
                message = "Detected IP spoofing from {}".format(ip_src)
                logging.warning(message)
                self.block_ip(ip_src)
                return {"message": "IP spoofing detected and blocked", "ip": ip_src}
            else:
                logging.info("No IP spoofing detected for packet: IP src {0}, IP dst {1}".format(ip_src, ip_dst))
        return {"message": "No IP spoofing detected"}

    def detect_ddos_attack(self, packet):
        if packet and packet.haslayer(IP):
            ip_src = packet[IP].src

            # Увеличиваем счетчик пакетов для IP
            self.ip_syn_count[ip_src] += 1

            # Проверка на превышение порога
            if self.ip_syn_count[ip_src] > 100:
                message = "Detected potential DDOS attack from {}".format(ip_src)
                logging.warning(message)
                self.block_ip(ip_src)
                return {"message": message, "ip": ip_src}
            else:
                logging.info("No DDOS attack detected for IP {0}. Count: {1}".format(ip_src, self.ip_syn_count[ip_src]))
        return {"message": "No DDOS attack detected"}

    def detect_session_hijacking(self, packet):
        if packet and packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_flags = packet[TCP].flags

            logging.info("Analyzing packet: IP src {0}, IP dst {1}, TCP sport {2}, TCP dport {3}".format(
                ip_src, ip_dst, packet[TCP].sport, packet[TCP].dport))
            # Проверка на аномальные флаги TCP
            if tcp_flags == "SA":  # Флаги SYN-ACK
                message = "Detected potential session hijacking from {}".format(ip_src)
                logging.warning(message)
                self.block_ip(ip_src)
                return {"message": message, "ip": ip_src}
        return {"message": "No session hijacking detected"}

    def detect_port_scanning(self, packet):
        if packet and packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            tcp_dport = packet[TCP].dport

            # Увеличиваем счетчик сканирований портов для IP
            self.port_scan_count[ip_src] += 1

            logging.info("Traffic captured: {0} to {1}".format(packet[IP].src, packet[IP].dst))

            # Проверка на превышение порога
            if self.port_scan_count[ip_src] > 50:  # Пример порога
                message = "Detected potential port scanning from {}".format(ip_src)
                logging.warning(message)
                self.block_ip(ip_src)
                return {"message": message, "ip": ip_src}
        return {"message": "No port scanning detected"}

    def block_ip(self, ip_address):
        if ip_address not in self.ip_block_time or self.ip_block_time[ip_address] == datetime.min:
            rule = "iptables -A INPUT -s " + str(ip_address) + " -j DROP"
            subprocess.run(rule, shell=True)
            self.ip_block_time[ip_address] = datetime.now()
            logging.warning("IP address " + str(ip_address) + " has been blocked due to suspicious activity.")
        else:
            last_blocked_time = self.ip_block_time[ip_address]
            current_time = datetime.now()
            # Логирование только один раз в 5 минут
            if (current_time - last_blocked_time).total_seconds() > 300:
                logging.info("Repeated attempt to block IP address " + str(ip_address))
                self.ip_block_time[ip_address] = current_time


# monitor = NetworkSecurityMonitor('traffic_data.csv', 'classification_report.txt')

# Определение маршрута API для доступа к данным о трафике
@app.route('/traffic', methods=['GET'])
def get_traffic_data():
    return jsonify(monitor.traffic_data)


# Определение маршрута API для запуска сниффера
@app.route('/start_sniffer', methods=['POST'])
def start_sniffer():
    monitor.run_sniffer()
    return jsonify({'message': 'Sniffer started'})


# Определение маршрута API для остановки сниффера
@app.route('/stop_sniffer', methods=['POST'])
def stop_sniffer():
    monitor.stop_sniffer()
    return jsonify({'message': 'Sniffer stopped'})


# Определение маршрута API для получения отчета
@app.route('/report', methods=['GET'])
def get_report():
    report = monitor.generate_report()
    return jsonify(report)


@app.route('/detect_ip_spoofing', methods=['POST'])
def detect_ip_spoofing_route():
    try:
        packet_data = request.get_json()
        if not packet_data:
            logging.error("No packet data provided")
            return jsonify({"message": "No packet data provided"}), 400

        packet = Ether(packet_data)
        logging.info("Received request to detect IP spoofing")
        result = monitor.detect_ip_spoofing(packet)
        return jsonify(result)
    except Exception as e:
        logging.error("Exception occurred: {}".format(e))
        return jsonify({"message": "Error occurred"}), 500

@app.route('/detect_ddos_attack', methods=['POST'])
def detect_ddos_attack_route():
    try:
        packet_data = request.get_json()
        if not packet_data:
            logging.error("No packet data provided")
            return jsonify({"message": "No packet data provided"}), 400

        packet = Ether(packet_data)
        logging.info("Received request to detect DDOS attack")
        result = monitor.detect_ddos_attack(packet)
        return jsonify(result)
    except Exception as e:
        logging.error("Exception occurred: {}".format(e))
        return jsonify({"message": "Error occurred"}), 500

@app.route('/detect_session_hijacking', methods=['POST'])
def detect_session_hijacking_route():
    try:
        packet_data = request.get_json()
        if not packet_data:
            logging.error("No packet data provided")
            return jsonify({"message": "No packet data provided"}), 400

        packet = Ether(packet_data)
        logging.info("Received request to detect session hijacking")
        result = monitor.detect_session_hijacking(packet)
        return jsonify(result)
    except Exception as e:
        logging.error("Exception occurred: {}".format(e))
        return jsonify({"message": "Error occurred"}), 500

@app.route('/detect_port_scanning', methods=['POST'])
def detect_port_scanning_route():
    try:
        packet_data = request.get_json()
        if not packet_data:
            logging.error("No packet data provided")
            return jsonify({"message": "No packet data provided"}), 400

        packet = Ether(packet_data)
        logging.info("Received request to detect port scanning")
        result = monitor.detect_port_scanning(packet)
        return jsonify(result)
    except Exception as e:
        logging.error("Exception occurred: {}".format(e))
        return jsonify({"message": "Error occurred"}), 500

# Обработка исключений и логирование ошибок
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error("Exception occurred: {}".format(e))
    response = jsonify({'message': str(e)})
    response.status_code = 500
    return response

if __name__ == "__main__":
    monitor = NetworkSecurityMonitor('traffic_data.csv', 'classification_report.txt')
    print("Starting Flask app...")
    app.run(debug=True, port=5002)  # Измените порт здесь
