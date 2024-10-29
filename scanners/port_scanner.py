# scanners/port_scanner.py

import socket
import ssl
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging

# Configura il logging
logging.basicConfig(filename='port_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class PortScanner:
    """
    Classe per effettuare la scansione delle porte su un indirizzo IP specifico
    e rilevare le versioni dei servizi in esecuzione.
    """

    def __init__(self, timeout=2, retries=2, max_workers=100):
        """
        Inizializza il PortScanner con timeout e retries configurabili.
        """
        self.timeout = timeout
        self.retries = retries
        self.max_workers = max_workers

    def scan_ports(self, ip_address, output_text_widget, domain_name=None):
        """
        Scansiona una lista predefinita di porte sull'indirizzo IP fornito
        e tenta di rilevare la versione del servizio su porte aperte.
        Se la porta 443 è aperta e il dominio è disponibile, esegue una scansione SSL sul dominio.
        """
        # Lista di porte comuni da scansionare
        target_ports = [
            1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49,
            53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119,
            137, 139, 143, 150, 156, 161, 162, 179, 190, 194, 197,
            389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 587,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017
        ]

        output_text_widget.insert(tk.END, f"[{datetime.now()}] Inizio scansione porte...\n")
        logging.info(f"Inizio scansione porte su {ip_address}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, ip_address, port): port for port in target_ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    output_text_widget.insert(tk.END, result)
                    logging.info(result.strip())
                    # Se la porta 443 è aperta e il dominio è disponibile, esegui la scansione SSL
                    if port == 443 and "è aperta" in result and domain_name:
                        ssl_result = self.scan_ssl(domain_name, 443)
                        output_text_widget.insert(tk.END, ssl_result)
                        logging.info(ssl_result.strip())
                except Exception as e:
                    error_msg = f"Errore durante la scansione della porta {port}: {e}\n"
                    output_text_widget.insert(tk.END, error_msg)
                    logging.error(error_msg.strip())

        output_text_widget.insert(tk.END, f"[{datetime.now()}] Scansione porte completata.\n")
        logging.info("Scansione porte completata.")

    def fast_scan(self, ip_address, output_text_widget, domain_name=None):
        """
        Esegue una scansione rapida di una lista ridotta di porte comuni
        sull'indirizzo IP fornito e tenta di rilevare la versione del servizio.
        Se la porta 443 è aperta e il dominio è disponibile, esegue una scansione SSL sul dominio.
        """
        # Lista ridotta di porte comuni per una scansione rapida
        target_ports = [22, 21, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]

        output_text_widget.insert(tk.END, f"[{datetime.now()}] Inizio scansione rapida delle porte...\n")
        logging.info(f"Inizio scansione rapida delle porte su {ip_address}")

        with ThreadPoolExecutor(max_workers=self.max_workers // 2) as executor:
            future_to_port = {executor.submit(self.scan_port, ip_address, port): port for port in target_ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    output_text_widget.insert(tk.END, result)
                    logging.info(result.strip())
                    # Se la porta 443 è aperta e il dominio è disponibile, esegui la scansione SSL
                    if port == 443 and "è aperta" in result and domain_name:
                        ssl_result = self.scan_ssl(domain_name, 443)
                        output_text_widget.insert(tk.END, ssl_result)
                        logging.info(ssl_result.strip())
                except Exception as e:
                    error_msg = f"Errore durante la scansione della porta {port}: {e}\n"
                    output_text_widget.insert(tk.END, error_msg)
                    logging.error(error_msg.strip())

        output_text_widget.insert(tk.END, f"[{datetime.now()}] Scansione rapida completata.\n")
        logging.info("Scansione rapida completata.")

    def scan_port(self, ip_address, port):
        """
        Scansiona una singola porta e tenta di rilevare la versione del servizio.
        """
        for attempt in range(1, self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        service_version = self.get_service_version(sock, ip_address, port)
                        return f"Porta {port} è aperta - {service_version}\n"
                    else:
                        return f"Porta {port} è chiusa\n"
            except socket.timeout:
                logging.warning(f"Timeout sulla porta {port}, tentativo {attempt}/{self.retries}")
                if attempt == self.retries:
                    return f"Porta {port} - Timeout dopo {self.retries} tentativi\n"
            except Exception as e:
                return f"Errore sulla porta {port}: {e}\n"

    def get_service_version(self, sock, ip_address, port):
        """
        Tenta di rilevare la versione del servizio in esecuzione sulla porta aperta.
        """
        service_info = "Versione non rilevata"

        try:
            # Impostare un timeout più lungo per le operazioni di ricezione
            sock.settimeout(2)
            if port in [80, 8080, 443, 8443]:
                # HTTP/HTTPS: invia una richiesta HTTP GET semplice
                http_request = f"GET / HTTP/1.1\r\nHost: {ip_address}\r\n\r\n"
                if port in [443, 8443]:
                    # HTTPS: avvolge il socket con SSL
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                        ssock.sendall(http_request.encode())
                        response = ssock.recv(1024).decode(errors='ignore')
                else:
                    sock.sendall(http_request.encode())
                    response = sock.recv(1024).decode(errors='ignore')
                service_info = self.parse_http_response(response)
            elif port == 21:
                # FTP: ricevi il banner
                response = sock.recv(1024).decode(errors='ignore')
                service_info = response.strip()
            elif port == 22:
                # SSH: ricevi il banner
                response = sock.recv(1024).decode(errors='ignore')
                service_info = response.strip()
            elif port == 25:
                # SMTP: ricevi il banner
                response = sock.recv(1024).decode(errors='ignore')
                service_info = response.strip()
            else:
                # Altri servizi: tenta di ricevere un banner generico
                response = sock.recv(1024).decode(errors='ignore')
                if response:
                    service_info = response.strip()
        except socket.timeout:
            service_info = "Timeout nella rilevazione del servizio"
        except ssl.SSLError as e:
            service_info = f"Errore SSL: {e}"
        except Exception as e:
            service_info = f"Errore nella rilevazione del servizio: {e}"

        return service_info

    def parse_http_response(self, response):
        """
        Analizza la risposta HTTP per estrarre informazioni sulla versione del server.
        """
        lines = response.split("\r\n")
        for line in lines:
            if line.startswith("Server:"):
                return line
        return "Server: Non rilevato"

    def scan_ssl(self, domain_name, port):
        """
        Esegue una scansione SSL sul dominio specificato e tenta di estrarre informazioni sul certificato.
        """
        service_info = "Versione SSL non rilevata"

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_name, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                    # Recupera il certificato SSL
                    cert = ssock.getpeercert()
                    # Estrae informazioni utili dal certificato
                    server = cert.get('subject', [])
                    server = dict(x[0] for x in server)
                    common_name = server.get('commonName', '')
                    organization = cert.get('issuer', [])
                    organization = dict(x[0] for x in organization)
                    organization_name = organization.get('commonName', '')
                    service_info = f"SSL Certificate: CN={common_name}, O={organization_name}"
        except ssl.CertificateError as e:
            service_info = f"Errore SSL: {e}"
        except ssl.SSLError as e:
            service_info = f"Errore SSL: {e}"
        except socket.timeout:
            service_info = "Timeout durante la scansione SSL"
        except Exception as e:
            service_info = f"Errore durante la scansione SSL: {e}"

        return service_info
