import time

def check_arp_spoofing(packet, trusted_hosts):
    """
    Verifica se um pacote ARP indica um possível ataque de ARP Spoofing.
    Compara o pacote com uma tabela de hosts conhecidos e confiáveis.
    
    :param packet: O pacote Pyshark a ser analisado.
    :param trusted_hosts: Dicionário com mapeamento IP -> MAC confiável.
    :return: Um dicionário de alerta se uma anomalia for encontrada, senão None.
    """
    # Só nos importamos com pacotes ARP.
    if 'ARP' in packet:
        # O 'opcode' 2 significa que é uma resposta ARP ("is-at").
        if packet.arp.opcode == '2':
            source_ip = packet.arp.src_proto_ipv4
            source_mac = packet.arp.src_hw_mac
            
            # Verifica se o IP de origem está na nossa lista de hosts confiáveis.
            if source_ip in trusted_hosts:
                trusted_mac = trusted_hosts[source_ip]

                # Normaliza ambos os endereços MAC para um formato único antes de comparar.
                # ex: 'c87f54534fbe'
                mac_do_pacote_normalizado = source_mac.lower().replace(':', '').replace('-', '')
                mac_confiavel_normalizado = trusted_mac.lower().replace(':', '').replace('-', '')
                
                # Se o MAC no pacote for diferente do MAC que consideramos confiável...
                if mac_do_pacote_normalizado != mac_confiavel_normalizado:
                    # ... temos uma potencial anomalia!
                    alert = {
                        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        "alert_type": "ARP_SPOOFING_DETECTED",
                        "source_ip": source_ip,
                        "source_mac": source_mac,
                        "details": f"Dispositivo {source_ip} anunciou o MAC {source_mac}, mas o MAC confiável registrado é {trusted_mac}."
                    }
                    return alert
    
    # Se não for um pacote ARP suspeito, não retorna nada.
    return None

def check_syn_flood(packet, syn_counters, threshold, window):
    """
    Verifica se um pacote TCP SYN faz parte de um possível ataque de SYN Flood.
    Utiliza um dicionário para contar pacotes por IP em uma janela de tempo.
    
    :param packet: O pacote Pyshark a ser analisado.
    :param syn_counters: Dicionário para manter o estado (contagem/timestamps).
    :param threshold: O número de pacotes SYN para disparar o alerta.
    :param window: A janela de tempo em segundos.
    :return: Um dicionário de alerta se o limiar for atingido, senão None.
    """
    # Só nos importamos com pacotes TCP que são pedidos de sincronização (SYN).
    # A flag SYN estará '1' e a flag ACK estará '0'.
    if hasattr(packet, 'tcp') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
        source_ip = packet.ip.src
        current_time = time.time()
        
        # Se o IP não estiver no nosso dicionário de contagem, inicializa-o com uma lista vazia.
        if source_ip not in syn_counters:
            syn_counters[source_ip] = []
            
        # Adiciona o timestamp do pacote atual à lista daquele IP.
        syn_counters[source_ip].append(current_time)
        
        # Filtramos a lista, mantendo apenas os timestamps que estão dentro da janela de tempo.
        syn_counters[source_ip] = [ts for ts in syn_counters[source_ip] if current_time - ts < window]
        
        # Verifica se a contagem de pacotes na janela de tempo ultrapassou o limiar.
        packet_count_in_window = len(syn_counters[source_ip])
        if packet_count_in_window > threshold:
            
            # Limpa o contador para este IP para não gerar alertas repetidos para o mesmo flood.
            syn_counters[source_ip] = []
            
            alert = {
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "alert_type": "SYN_FLOOD_DETECTED",
                "source_ip": source_ip,
                "destination_ip": packet.ip.dst,
                "details": f"Detectados {packet_count_in_window} pacotes SYN de {source_ip} em menos de {window} segundos, excedendo o limiar de {threshold}."
            }
            return alert
            
    return None

def check_port_scan(packet, port_scan_tracker, threshold, window):
    """
    Verifica se um pacote TCP SYN faz parte de uma varredura de portas.
    """
    if hasattr(packet, 'tcp') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
        source_ip = packet.ip.src
        dest_ip = packet.ip.dst
        dest_port = packet.tcp.dstport
        current_time = time.time()
        
        # Criamos uma chave única para o par origem-destino.
        tracker_key = f"{source_ip}:{dest_ip}"
        
        if tracker_key not in port_scan_tracker:
            port_scan_tracker[tracker_key] = []
            
        # Adiciona a tupla (porta, timestamp) à lista.
        port_scan_tracker[tracker_key].append((dest_port, current_time))
        
        # Remove registros antigos da janela de tempo.
        port_scan_tracker[tracker_key] = [
            record for record in port_scan_tracker[tracker_key] if current_time - record[1] < window
        ]
        
        # Conta o número de portas ÚNICAS na janela de tempo.
        scanned_ports = {record[0] for record in port_scan_tracker[tracker_key]}
        
        if len(scanned_ports) > threshold:
            # Limpa o rastreador para este par para não gerar alertas repetidos.
            port_scan_tracker[tracker_key] = []
            
            alert = {
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "alert_type": "PORT_SCAN_DETECTED",
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "details": f"{source_ip} escaneou {len(scanned_ports)} portas diferentes em {dest_ip} em menos de {window} segundos."
            }
            return alert
            
    return None
