# teste_logica_syn.py

import time
from types import SimpleNamespace

# Importamos apenas a função que queremos testar
from detectors import check_syn_flood

print("--- INICIANDO TESTE DE UNIDADE PARA O DETECTOR DE SYN FLOOD ---")

# 1. Preparamos o ambiente de teste
syn_counters_teste = {}
LIMIAR = 100
JANELA_DE_TEMPO = 5

# 2. Criamos um "pacote falso" (mock object)
#    Nossa função só precisa de alguns campos, então não precisamos de um pacote real.
#    SimpleNamespace nos permite criar um objeto simples com atributos.
pacote_falso = SimpleNamespace(
    ip=SimpleNamespace(src='10.10.10.10', dst='20.20.20.20'),
    tcp=SimpleNamespace(flags_syn='1', flags_ack='0')
)

print(f"[*] Simulando a chegada de {LIMIAR + 1} pacotes SYN em menos de 1 segundo...")

# 3. Executamos a lógica de ataque em um loop
alerta_gerado = None
for i in range(LIMIAR + 1): # Enviamos 101 pacotes
    alerta = check_syn_flood(
        pacote_falso,
        syn_counters_teste,
        LIMIAR,
        JANELA_DE_TEMPO
    )
    if alerta:
        alerta_gerado = alerta
        break # Para o loop assim que o alerta for gerado
    
    time.sleep(0.005) # Pequeno intervalo entre pacotes

# 4. Verificamos o resultado
print("\n--- RESULTADO DO TESTE ---")
if alerta_gerado:
    print("[+] SUCESSO! O detector de SYN Flood gerou um alerta corretamente.")
    print("    Detalhes do Alerta Gerado:")
    for key, value in alerta_gerado.items():
        print(f"      {key}: {value}")
else:
    print("[!] FALHA: O loop terminou mas nenhum alerta foi gerado.")

print("\n--- TESTE FINALIZADO ---")