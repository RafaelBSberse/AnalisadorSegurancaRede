import pyshark
import sys
import time
from analysis_engine import AnalysisEngine

def find_active_interface():
    """
    Tenta encontrar uma interface de rede funcional a partir de uma lista de nomes comuns.
    Retorna um objeto de captura do Pyshark se for bem-sucedido, ou None se falhar.
    """
    interfaces_preferidas = [
        'Ethernet',
        'Wi-Fi',
        'eth0',
        'en0',
        'wlan0'
    ]
    
    print("Iniciando... Procurando por uma interface de rede ativa.")
    
    for interface in interfaces_preferidas:
        try:
            print(f"[*] Tentando interface '{interface}'...")
            # Tenta criar o objeto de captura. Se a interface não existir, isso falhará.
            capture = pyshark.LiveCapture(interface=interface)
            # Faz uma micro-captura para garantir que a interface está realmente funcionando.
            capture.sniff(timeout=0.1)
            print(f"[+] Sucesso! Capturando pacotes na interface '{interface}'.")
            return capture
        except Exception:
            print(f"[-] Interface '{interface}' não encontrada ou sem permissão. Tentando a próxima...")

    return None

def main():
    """
    Função principal que orquestra a captura e a análise.
    """
    # 1. Encontra a interface e inicia o objeto de captura.
    capture = find_active_interface()
    
    if capture is None:
        print("\n[!] ERRO: Nenhuma interface de rede funcional foi encontrada.")
        print("    Verifique suas conexões e permissões (execute como admin/sudo).")
        sys.exit(1)
        
    # 2. Cria uma instância do nosso motor de análise.
    #    O motor carregará as configurações e manterá o estado da análise.
    engine = AnalysisEngine()
    
    print("\n[+] Motor de Análise iniciado. Monitorando o tráfego...")
    print("    Pressione Ctrl+C para parar a captura.")
    
    try:
        # 3. Inicia o loop infinito de captura.
        #    Para cada pacote capturado, a função do motor de análise é chamada.
        for packet in capture.sniff_continuously():
            engine.process_packet(packet)
            
    except KeyboardInterrupt:
        print("\n[*] Captura interrompida pelo usuário.")
    except Exception as e:
        print(f"\n[!] Um erro inesperado ocorreu: {e}")
    finally:
        # 4. Garante que a captura seja fechada corretamente.
        if capture and capture.eventloop.is_running():
            capture.close()
        print("[*] Programa finalizado.")

# Ponto de entrada padrão para um script Python.
if __name__ == "__main__":
    main()