# Proiect LP3
# Captare și analiza pachetelor de date
# Proiect realizat de: Alexandru Hadaruga, Andrei Dome
# requirements scapy si npcap (windows) 

from scapy.all import conf
conf.use_pcap = True  # Folosește librăria pcap pentru capturarea pachetelor

from scapy.all import sniff  # Importă funcția sniff pentru capturarea pachetelor
import atexit  # Importă atexit pentru a înregistra o funcție care să fie apelată la ieșirea din program
import sys  # Importă sys pentru a putea ieși din program în mod curat
from datetime import datetime  # Importă datetime pentru a putea lucra cu date și ore

# Lista pentru stocarea pachetelor capturate
packets = []

# Funcția callback care va fi apelată pentru fiecare pachet capturat
def packet_callback(packet):
    packets.append(packet)  # Adaugă pachetul în lista de pachete
    print(packet.summary())  # Afișează un sumar al pachetului

# Funcția pentru salvarea pachetelor în fișier text
def save_packets_to_text():
    with open('captured_packets.txt', 'w') as f:  # Deschide fișierul pentru scriere
        f.write("Pachete Capturate:\n")  # Scrie un header în fișier
        for packet in packets:
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')  # Formatează timestamp-ul pachetului
            f.write(f"Timp: {timestamp}\n")  # Scrie timestamp-ul în fișier
            if packet.haslayer('IP'):
                ip_src = packet['IP'].src  # Obține adresa IP sursă
                ip_dst = packet['IP'].dst  # Obține adresa IP destinație
                f.write(f"IP Sursa: {ip_src}\n")  # Scrie adresa IP sursă în fișier
                f.write(f"IP Destinatie: {ip_dst}\n")  # Scrie adresa IP destinație în fișier
            if packet.haslayer('TCP'):
                tcp_sport = packet['TCP'].sport  # Obține portul sursă TCP
                tcp_dport = packet['TCP'].dport  # Obține portul destinație TCP
                f.write(f"Port Sursa: {tcp_sport}\n")  # Scrie portul sursă în fișier
                f.write(f"Port Destinatie: {tcp_dport}\n")  # Scrie portul destinație în fișier
                f.write(f"Protocol: TCP\n")  # Scrie protocolul TCP în fișier
            elif packet.haslayer('UDP'):
                udp_sport = packet['UDP'].sport  # Obține portul sursă UDP
                udp_dport = packet['UDP'].dport  # Obține portul destinație UDP
                f.write(f"Port Sursa: {udp_sport}\n")  # Scrie portul sursă în fișier
                f.write(f"Port Destinatie: {udp_dport}\n")  # Scrie portul destinație în fișier
                f.write(f"Protocol: UDP\n")  # Scrie protocolul UDP în fișier
            elif packet.haslayer('ICMP'):
                f.write(f"Protocol: ICMP\n")  # Scrie protocolul ICMP în fișier
            f.write(f"Raw Data: {bytes(packet)}\n")  # Scrie datele brute ale pachetului în fișier
            f.write("="*50 + "\n")  # Scrie un separator pentru pachete
    print(f"\nSaved {len(packets)} packets to captured_packets.txt")  # Afișează un mesaj cu numărul de pachete salvate

# Înregistrează funcția save_packets_to_text să fie apelată la ieșirea din program
atexit.register(save_packets_to_text)

if __name__ == '__main__':
    print("Incepe Capturarea de Pachete. Apasa Ctrl+C ca sa opresti executia si sa salvezi in fisier")  # Mesaj de start pentru capturarea pachetelor
    try:
        sniff(prn=packet_callback)  # Începe capturarea pachetelor și folosește packet_callback pentru procesarea lor
    except KeyboardInterrupt:
        print("\nCapturarea de Pachete a fost Oprita!")  # Mesaj de oprire a capturării pachetelor
        sys.exit(0)  # Ieșire curată din program
