---

# Network Scanner Enumerator v2.0

![License](https://img.shields.io/badge/license-MIT-blue.svg)  
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)

## Descrizione

**Network Scanner Enum** è un'applicazione Python dotata di un'interfaccia grafica che consente di eseguire vari tipi di scansioni di rete su un indirizzo IP o URL specificato. Le funzionalità includono:

- **Fast Scan**: Scansione rapida delle porte comuni.
- **Ports Scan**: Scansione dettagliata su una lista predefinita di porte.
- **OS Detection**: Rilevamento del sistema operativo basato sul valore TTL.
- **SMB Enumeration**: Enumerazione delle condivisioni e degli utenti SMB.
- **FTP Enumeration**: Enumerazione dei file su un server FTP.
- **SSL Certificate Information**: Recupero e visualizzazione delle informazioni sui certificati SSL per i domini scansionati sulla porta 443.

Questa applicazione è particolarmente utile per amministratori di rete, professionisti della sicurezza informatica e appassionati che desiderano monitorare e analizzare le reti in modo efficace e intuitivo.

## Screenshot

![Screenshot della GUI di Network Scanner](screenshot.png)

## Tecnologie Utilizzate

- **Python 3.x**
- **Tkinter**: per l'interfaccia grafica
- **ftplib**: per l'enumerazione FTP
- **pysmb**: per l'enumerazione SMB
- **socket**: per le operazioni di rete
- **ssl**: per la scansione dei certificati SSL
- **concurrent.futures**: per la gestione dei thread

## Installazione

Segui questi passaggi per installare e configurare il progetto sul tuo sistema locale.

### 1. Clona il Repository

Clona il repository sul tuo computer utilizzando `git`:

```bash
git clone https://github.com/francescobrina/network_scanner_enum.git
```

---

Questa struttura rende il contenuto chiaro e ben organizzato. Assicurati di aggiungere eventuali dettagli aggiuntivi come requisiti di sistema o istruzioni di configurazione se necessario.

### 2. Naviga nella Directory del Progetto

```bash
cd network_scanner_enum
```

### 3. Crea un Ambiente Virtuale (Opzionale ma Consigliato)

Creare un ambiente virtuale ti aiuta a gestire le dipendenze del progetto in modo isolato.

```bash
python -m venv venv
```

### 4. Attiva l'Ambiente Virtuale

- **Su Windows:**

  ```bash
  venv\Scripts\activate
  ```

- **Su Unix o MacOS:**

  ```bash
  source venv/bin/activate
  ```

### 5. Installa le Dipendenze

Assicurati di avere `pip` aggiornato e installa le dipendenze necessarie:

```bash
pip install -r requirements.txt
```

**Nota:** Su alcune distribuzioni Linux, potrebbe essere necessario installare `tkinter` separatamente. Ad esempio, su distribuzioni basate su Debian/Ubuntu:

```bash
sudo apt-get install python3-tk
```

## Utilizzo

Esegui l'applicazione con il seguente comando:

```bash
python main.py
```

### Passaggi:

1. **Inserisci l'Indirizzo IP o l'URL:**
   - Puoi inserire un indirizzo IP (es. `192.168.1.1`) o un URL (es. `www.example.com`).

2. **Seleziona il Tipo di Scansione:**
   - **Fast Scan:** Scansione rapida di porte comuni.
   - **Ports Scan:** Scansione dettagliata di una lista predefinita di porte.
   - **OS Detection:** Rilevamento del sistema operativo basato sul valore TTL.
   - **SMB Enumeration:** Enumerazione delle condivisioni e degli utenti SMB.
   - **FTP Enumeration:** Enumerazione dei file presenti su un server FTP.
   - **SSL Certificate Information:** Recupero delle informazioni del certificato SSL per i domini scansionati sulla porta 443.

3. **Avvia la Scansione:**
   - Clicca su "Avvia Scansione" per iniziare. I risultati verranno mostrati nell'area di output.

### Esempio di Output

#### Informazioni del Certificato SSL

Quando scansioni un sito con la porta **443** aperta, l'applicazione eseguirà una scansione SSL sul nome di dominio per ottenere informazioni sul certificato SSL.

**Esempio di Output:**

```
Porta 443 è aperta - Server: Apache/2.X.XX (Ubuntu)
SSL Certificate: CN=example.com, O=R10

[2024-10-29 19:36:35.306444] Scansione porte completata.
```

## Contribuire

Sono benvenute le pull request! Se desideri contribuire al progetto, segui questi passaggi:

1. **Fork del Repository:**
   - Clicca sul pulsante "Fork" in alto a destra sulla pagina del repository.

2. **Clona il Tuo Fork:**

   ```bash
   git clone https://github.com/tuo-username/network_scanner_enum.git
   ```

3. **Crea un Nuovo Branch:**

   ```bash
   git checkout -b feature/nome-feature
   ```

4. **Fai le Tue Modifiche e Commit:**

   ```bash
   git commit -m "Aggiunta di [descrizione della feature]"
   ```

5. **Pusha le Modifiche al Tuo Fork:**

   ```bash
   git push origin feature/nome-feature
   ```

6. **Apri una Pull Request:**
   - Vai al repository originale e apri una pull request dal tuo fork.

## Licenza

Questo progetto è sotto licenza MIT.

## Autore

**Francesco Brina**  
[francescobrina9@gmail.com](mailto:francescobrina9@gmail.com)  

LinkedIn: [linkedin.com/in/francescobrina](https://linkedin.com/in/francescobrina)  
GitHub: [github.com/francescobrina](https://github.com/francescobrina)

## Ringraziamenti

- Grazie a tutte le librerie e gli strumenti open-source che hanno reso questo progetto possibile.
---

## Note Importanti

- **Uso Etico e Legale:** Assicurati di avere l'autorizzazione per scansionare gli indirizzi IP o i siti web target. L'esecuzione di scansioni di rete su sistemi senza permesso può essere illegale e non etico.
- **Limitazioni del Tool:** Utilizzalo come supporto e non come unica fonte di analisi.
- **Responsabilità:** Sei responsabile dell'uso che fai di questo software. Utilizzalo solo per scopi legittimi ed etici.

---

## FAQ

### 1. Perché la scansione FTP fallisce con un timeout?

Assicurati che il server FTP sia accessibile e che la porta 21 sia aperta. Il programma in automatico e informa se il server FTP supporta il login anonimo. Se il server richiede credenziali specifiche, l'enumerazione FTP potrebbe fallire.

### 2. Come posso aggiungere ulteriori funzionalità al tool?

Puoi contribuire al progetto creando una nuova branch, aggiungendo le funzionalità desiderate e aprendo una pull request. Assicurati di seguire le linee guida di contribuzione riportate in questa sezione.

### 3. Posso utilizzare questo tool su qualsiasi sistema operativo?

Il tool è stato sviluppato e testato su Windows e Unix/Linux. Assicurati di avere Python 3.x installato e le dipendenze necessarie per eseguire l'applicazione.

---

Se hai ulteriori domande o necessiti di assistenza aggiuntiva, non esitare a contattarmi!
``` 
