import json
import time

# Importa as funções dos nossos outros módulos.
# Note que elas ainda não existem, nós as criaremos a seguir.
import detectors
import logger

class AnalysisEngine:
    """
    Classe que gerencia o estado e orquestra a análise dos pacotes.
    """
    def __init__(self, config_file='hosts_confiaveis.json'):
        """
        Construtor da classe. É executado quando um objeto AnalysisEngine é criado.
        """
        print("[*] Inicializando o Motor de Análise...")
        
        # Carrega a lista de hosts confiáveis a partir de um arquivo de configuração.
        self.trusted_hosts = self._load_config(config_file)
        
        # Estruturas de dados para manter o estado dos detectores.
        # Para o SYN Flood, vamos armazenar os timestamps dos pacotes SYN por IP.
        self.syn_counters = {}  # Formato: {'ip_origem': [timestamp1, timestamp2, ...]}
        self.SYN_FLOOD_THRESHOLD = 100     # 100 pacotes SYN
        self.SYN_FLOOD_WINDOW_SECONDS = 5  # em 5 segundos.
        
        # Para o Port Scan, vamos armazenar as portas escaneadas por IP.
        # Usamos um dicionário onde a chave é uma string 'ip_origem:ip_destino'
        # e o valor é uma lista de tuplas (porta, timestamp).
        self.port_scan_tracker = {} # Formato: {'ip_origem:ip_destino': [(porta, timestamp), ...]}
        self.PORT_SCAN_THRESHOLD = 20  # Ex: 20 portas diferentes em 10 segundos.
        self.PORT_SCAN_WINDOW_SECONDS = 10

    def _load_config(self, config_file):
        """
        Método privado para carregar o arquivo de configuração JSON.
        """
        try:
            with open(config_file, 'r') as f:
                trusted_hosts = json.load(f)
                print(f"[+] Arquivo de configuração '{config_file}' carregado com sucesso.")
                return trusted_hosts
        except FileNotFoundError:
            print(f"[!] AVISO: Arquivo de configuração '{config_file}' não encontrado.")
            print("    O detector de ARP Spoofing não funcionará sem ele.")
            return {} # Retorna um dicionário vazio se o arquivo não existir.
        except json.JSONDecodeError:
            print(f"[!] ERRO: O arquivo '{config_file}' não é um JSON válido.")
            return {}

    def process_packet(self, packet):
        """
        Método principal que processa cada pacote capturado.
        Ele chama os detectores apropriados.
        """
        # --- Detector de ARP Spoofing ---
        # Passamos o pacote e a tabela de hosts confiáveis que carregamos.
        arp_alert = detectors.check_arp_spoofing(packet, self.trusted_hosts)
        if arp_alert:
            logger.log_alert(arp_alert)

        # --- Detector de SYN Flood ---
        # Passamos o pacote, os contadores, o limiar e a janela de tempo.
        # Esta função irá modificar self.syn_counters diretamente (passado por referência).
        syn_flood_alert = detectors.check_syn_flood(
            packet, 
            self.syn_counters, 
            self.SYN_FLOOD_THRESHOLD, 
            self.SYN_FLOOD_WINDOW_SECONDS
        )
        if syn_flood_alert:
            logger.log_alert(syn_flood_alert)

        # --- Detector de Port Scan ---
        # Passamos o pacote, o rastreador de portas, o limiar e a janela de tempo.
        # Esta função irá modificar self.port_scan_tracker diretamente (passado por referência).
        port_scan_alert = detectors.check_port_scan(
            packet,
            self.port_scan_tracker,
            self.PORT_SCAN_THRESHOLD,
            self.PORT_SCAN_WINDOW_SECONDS
        )
        if port_scan_alert:
            logger.log_alert(port_scan_alert)
