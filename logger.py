import json
import os
import threading

# Criamos um "cadeado" (Lock) para garantir que, mesmo se o programa se tornasse
# mais complexo no futuro (com múltiplas threads), nunca haveria duas tentativas
# de escrever no arquivo de log ao mesmo tempo, o que poderia corrompê-lo.
log_lock = threading.Lock()

def log_alert(alert_data, log_file='security_log.json'):
    """
    Registra um dicionário de alerta em um arquivo de log no formato JSON.

    Esta função é 'thread-safe', o que significa que pode ser chamada de
    diferentes partes de um programa concorrente sem risco de corromper o arquivo.

    :param alert_data: Um dicionário contendo os detalhes do alerta.
    :param log_file: O nome do arquivo de log onde o alerta será salvo.
    """
    # Adquirimos o "cadeado". Qualquer outra chamada para esta função terá
    # que esperar esta terminar antes de poder continuar.
    with log_lock:
        
        # É útil imprimir o alerta no console para monitoramento em tempo real.
        alert_type = alert_data.get('alert_type', 'UNKNOWN_ALERT')
        source_ip = alert_data.get('source_ip', 'N/A')
        print(f"[!] ALERTA REGISTRADO: {alert_type} | Origem: {source_ip}")

        alerts = []
        try:
            # Se o arquivo já existe e não está vazio, lê o conteúdo existente.
            if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
                with open(log_file, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)
            
        except (json.JSONDecodeError, FileNotFoundError):
            # Se o arquivo não existe ou está corrompido/vazio,
            # simplesmente começamos com uma lista nova.
            alerts = []

        # Adiciona o novo alerta à lista de alertas.
        alerts.append(alert_data)

        # Escreve a lista completa de volta ao arquivo.
        # O modo 'w' apaga o conteúdo antigo e escreve o novo.
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                # json.dump escreve a lista no arquivo, formatada com 4 espaços de indentação.
                json.dump(alerts, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"[!] ERRO CRÍTICO: Não foi possível escrever no arquivo de log '{log_file}'. Erro: {e}")