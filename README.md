# Analisador de Segurança de Rede

Este projeto é uma ferramenta de monitoramento de segurança de rede desenvolvida em Python. Utilizando a biblioteca Pyshark, ele captura e analisa o tráfego de rede em tempo real para detectar atividades maliciosas e anomalias, registrando todos os eventos em um log estruturado para análise posterior.

## Funcionalidades

O sistema é capaz de detectar e alertar sobre os seguintes padrões de ataque:

* **Detecção de ARP Spoofing:** Monitora respostas ARP na rede para identificar tentativas de envenenamento de cache ARP.
* **Detecção de SYN Flood:** Identifica um volume anormalmente alto de pacotes TCP SYN vindos de uma única origem, caracterizando uma tentativa de ataque de negação de serviço (DoS).
* **Detecção de Port Scan:** Detecta atividades de reconhecimento onde um mesmo host tenta se conectar a um grande número de portas diferentes em um alvo.

## Arquitetura

O projeto segue uma arquitetura modular para separar as responsabilidades e garantir um código limpo e de fácil manutenção:

-   **`main.py`**: O orquestrador principal, responsável pela inicialização e pelo loop de captura.
-   **`analysis_engine.py`**: O cérebro da aplicação, que gerencia o estado da análise e despacha os pacotes para os detectores.
-   **`detectors.py`**: Contém a lógica pura e especializada para cada tipo de detecção.
-   **`logger.py`**: Módulo dedicado exclusivamente a formatar e escrever os alertas no arquivo de log.

## Instalação e Configuração

Siga os passos abaixo para configurar e executar o projeto.

### Pré-requisitos

-   Python 3.8 ou superior
-   **Wireshark** instalado, com o **TShark** acessível nas variáveis de ambiente (PATH) do sistema.
    -   *Dica: Durante a instalação do Wireshark no Windows, certifique-se de marcar a opção para adicionar o TShark ao PATH.*

### Passos

1.  **Clone o Repositório**
    ```bash
    git clone https://github.com/RafaelBSberse/AnalisadorSegurancaRede.git
    cd AnalisadorSegurancaRede
    ```

2.  **Instale as Dependências**
    O projeto utiliza a biblioteca Pyshark. Para instalá-la, execute o comando abaixo, que utiliza o arquivo `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure os Hosts Confiáveis**
    Para que o detector de ARP Spoofing funcione corretamente, crie um arquivo chamado `hosts_confiaveis.json` no mesmo diretório. Este arquivo define os mapeamentos de IP para MAC que a rede considera legítimos.

    *Exemplo de `hosts_confiaveis.json`:*
    ```json
    {
      "192.168.1.1": "c0:51:5c:94:03:98",
      "192.168.1.100": "c8:7f:54:53:4f:be"
    }
    ```
    *Use os comandos `ipconfig /all` (Windows) ou `ip a` e `arp -a` (Linux/macOS) para encontrar esses valores na sua rede.*

## Como Usar

Para iniciar o monitoramento, execute o script `main.py` com privilégios de administrador, que são necessários para a captura de pacotes.

**No Windows (em um terminal aberto como "Administrador"):**
```bash
python main.py
```

## Saída (Logs)
Os alertas detectados são exibidos em tempo real no console e gravados no arquivo security_log.json. Cada registro no log é um objeto JSON formatado para fácil leitura e processamento.

Exemplo de um alerta no security_log.json:
```json
[
    {
        "timestamp": "2025-07-07T16:30:00Z",
        "alert_type": "ARP_SPOOFING_DETECTED",
        "source_ip": "192.168.1.1",
        "source_mac": "DE:AD:BE:EF:CA:FE",
        "details": "Dispositivo 192.168.1.1 anunciou o MAC DE:AD:BE:EF:CA:FE, mas o MAC confiável registrado é c0:51:5c:94:03:98."
    }
]
```