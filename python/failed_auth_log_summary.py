import argparse
import re
from collections import Counter

DEFAULT_THRESHOLD = 5
DEFAULT_format = 'text'
DEFAULT_output = ''

timestamp_pattern = r"\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{2}\.\d{6}" #r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}\:\d{2}\:\d{2}"

'''
1. Scopo: Leggere un file di log di autenticazione (es. auth.log o un campione pubblico equivalente) e produrre un riepilogo rapido per il triage: chi ha fallito l'accesso, da quali IP sorgente e quali IP mostrano comportamenti ripetitivi (potenziale brute-force o password spraying).
'''

class Event:
    def __init__(self, timestamp, ip, utente_target):
        self.timestamp = timestamp
        self.ip = ip
        self.utente_target = utente_target

def failed_auth_log_summary(logfile, threshold, output_format, output):
    # Lettura sicura del file: aprire il file in lettura (UTF-8, con gestione di eventuali righe malformate o non decodificabili senza far crashare lo script).
    with open (logfile, "r") as file:
        logfile_lines = file.read().splitlines()

    # Parsing delle righe rilevanti: individuare le righe che rappresentano un tentativo di autenticazione fallito (ad esempio login SSH fallito)
    logfile_failed = [l for l in logfile_lines if 'Failed' in l] # TODO fai case sensitive

    events = []
    #print(logfile_failed)
    for log_line in logfile_failed:
        # Nov 20 10:18:02 debian-lab sshd[1102]: Failed password for root from 198.51.100.23 port 51990 ssh2 # TODO cancella riga
        #print(log_line)
        # estrazione timestamp
        timestamps_found = re.findall(timestamp_pattern, log_line)
        timestamp = '' if not timestamps_found else timestamps_found[0]

        ips_found = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log_line)
        ip = '' if not ips_found else ips_found[0]

        utente_target_found = re.findall(r"for (?:invalid user )?(\S+) from", log_line) # (\S+) capturing group dato da \S+ (qualsiasi carattere che sia non spazio) -- tengo solo questo
        utente_target = '' if not utente_target_found else utente_target_found[0]

        #print(timestamp + " " + ip + " " + utente_target)
        event = Event(timestamp, ip, utente_target)
        events.append(event)

    # Aggregazione e conteggio
    ## Contare il numero totale di tentativi falliti analizzati.
    num_tot_tentativi_falliti = len(logfile_failed)

    ## Contare i fallimenti per IP sorgente (ordinati dal più frequente al meno frequente).
    num_fallimenti_per_ip = Counter(event.ip for event in events)
    num_ip_unici_fallimenti = len({ev.ip for ev in events})

    ## Contare i fallimenti per username (utile per capire se provano utenti standard o nomi specifici).
    num_fallimenti_per_utente = Counter(event.utente_target for event in events)

    ## Tracciare, per ciascun IP, la lista/insieme degli utenti provati e l'intervallo temporale (primo e ultimo evento visto).
    #grouped: ip > utente_target > lista di timestamp
    grouped_events = {}

    for ev in events:
        if ev.ip not in grouped_events:
            grouped_events[ev.ip] = {}
        if ev.utente_target not in grouped_events[ev.ip]:
            grouped_events[ev.ip][ev.utente_target] = []
        grouped_events[ev.ip][ev.utente_target].append(ev.timestamp)

    ## Flagging / Triage base: evidenziare gli IP il cui conteggio è >= threshold.
    #ip_over_threshold = [(ip, cnt) for ip, cnt in num_fallimenti_per_ip.items() if cnt > threshold]
    ip_over_threshold = [ip for ip, cnt in num_fallimenti_per_ip.items() if cnt > threshold]

    '''
    4. Output atteso
    In modalità text (a terminale):
        - Riepilogo generale (righe lette, tentativi falliti totali, numero di IP unici).
        - Tabella o elenco ordinato dei Top IP con: IP, Tentativi, Utenti distinti, Flag (es. [ALERT >= 5] o [OK]).
        - Breve lista dei Top Username provati.
    In modalità json: una struttura pulita con metadati (file analizzato, soglia usata) e liste/dizionari per top_ips e top_users, così in futuro potrai riutilizzarla in altri script.
    '''

    if output_format == 'text':
        print(f"Numero di righe lette: {len(logfile_lines)}")
        print(f"Numero di tentativi falliti: {num_tot_tentativi_falliti}; numero di ip unici: {num_ip_unici_fallimenti}")
        print("\nNumero di fallimenti per IP:")
        for ip, cnt in num_fallimenti_per_ip.most_common():
            alert = f"[ALERT >= {threshold}]" if cnt >= threshold else ""
            print(f"\t{ip} --> {cnt} {alert}")

        print("\nNumero di fallimenti per utente destinatario:")
        for user, cnt in num_fallimenti_per_utente.most_common():
            print(f"\t{user} --> {cnt}")

        print("\nIntervalli di tempo per IP/user bersaglio:")
        #for ip in grouped_events:
        for ip, cnt in num_fallimenti_per_ip.most_common():
            general_alert = f"[ALERT >= {threshold}]" if cnt >= threshold else ""
            print(f"{ip} {general_alert}")
            for user in grouped_events[ip]:
                tms = grouped_events[ip][user]
                num_tentaivi_per_utente = len(tms)
                user_alert = f" [ALERT >= {threshold}]" if num_tentaivi_per_utente >= threshold else ""
                print(f"\t{user}{user_alert}: {tms[0]} - {tms[-1]}")

    elif output_format == 'json':
        print("json momoa")


def main():
    #parse input
    parser = argparse.ArgumentParser(description="Riassume un file di log.")
    parser.add_argument("logfile", help="Percorso del file di log da analizzare.") #arg obbligatorio
    parser.add_argument("--threshold", type=int, default=DEFAULT_threshold, help="Soglia minima di tentativi falliti per segnalare un IP come sospetto/rilevante.")
    parser.add_argument("--format", default=DEFAULT_format, dest="output_format", help="Formato dell'output a terminale o su file.")
    parser.add_argument("--output", default=DEFAULT_output, help="Percorso di un file dove salvare il report (es. output/summary.json o output/summary.txt).")

    args = parser.parse_args()

    failed_auth_log_summary(args.logfile, args.threshold, args.output_format, args.output)

if __name__ == '__main__':
    main()

