# teste_logica_portscan.py

import time
from types import SimpleNamespace

# Importamos a função específica que queremos testar do nosso módulo de detectores.
from detectors import check_port_scan

print("--- INICIANDO TESTE DE UNIDADE PARA O DETECTOR DE PORT SCAN ---")

# 1. PREPARAÇÃO DO AMBIENTE DE TESTE
#    Usaremos um limiar mais baixo para que o teste seja rápido.
#    O limiar no seu código de produção é 20, aqui usaremos 5.
LIMIAR_TESTE = 5
JANELA_DE_TEMPO = 10 # 10 segundos
port_scan_tracker_teste = {}

# 2. CRIAÇÃO DO PACOTE FALSO (MOCK)
#    Criamos um objeto que imita um pacote TCP SYN real, com os atributos
#    que a nossa função 'check_port_scan' espera encontrar.
pacote_falso = SimpleNamespace(
    tcp=SimpleNamespace(flags_syn='1', flags_ack='0', dstport=0), # A porta de destino será atualizada no loop
    ip=SimpleNamespace(src='10.10.10.10', dst='20.20.20.20')
)

print(f"[*] Simulando uma varredura em {LIMIAR_TESTE + 1} portas diferentes para exceder o limiar de {LIMIAR_TESTE}...")

# 3. EXECUÇÃO DA LÓGICA DE TESTE
alerta_gerado = None
# O loop vai de 1 até 6 (LIMIAR_TESTE + 1), testando as portas 1, 2, 3, 4, 5, e 6.
# O alerta deve ser gerado no pacote para a porta 6.
for porta_alvo in range(1, LIMIAR_TESTE + 2):
    # A cada iteração, mudamos a porta de destino do nosso pacote falso.
    pacote_falso.tcp.dstport = porta_alvo
    
    print(f"    -> Simulando pacote SYN para a porta {porta_alvo}")
    
    alerta = check_port_scan(
        pacote_falso,
        port_scan_tracker_teste,
        LIMIAR_TESTE,
        JANELA_DE_TEMPO
    )
    
    # Se o detector retornou um alerta, guardamos o resultado e saímos do loop.
    if alerta:
        alerta_gerado = alerta
        break
    
    time.sleep(0.05) # Pequeno intervalo para simular a realidade.

# 4. VERIFICAÇÃO DO RESULTADO
print("\n--- RESULTADO DO TESTE ---")
if alerta_gerado:
    print(f"[+] SUCESSO! O detector de Port Scan gerou um alerta corretamente ao atingir a {LIMIAR_TESTE + 1}ª porta única.")
    print("    Detalhes do Alerta Gerado:")
    # Usamos um loop para imprimir o dicionário de forma legível.
    for key, value in alerta_gerado.items():
        print(f"      {key}: {value}")
else:
    print(f"[!] FALHA: O loop testou {LIMIAR_TESTE + 1} portas mas nenhum alerta foi gerado.")

print("\n--- TESTE FINALIZADO ---")