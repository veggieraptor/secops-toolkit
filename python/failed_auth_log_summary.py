import argparse
import re
from collections import Counter

DEFAULT_THRESHOLD = 5
DEFAULT_FORMAT = "text"

TIMESTAMP_PATTERN = r"\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{2}\.\d{6}"
IP_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
USER_PATTERN = r"for (?:invalid user )?(\S+) from"

class Event:
    def __init__(self, timestamp, ip, target_users):
        self.timestamp = timestamp
        self.ip = ip
        self.target_users = target_users

def failed_auth_log_summary(logfile, threshold, output_format):
    # Lettura file
    with open (logfile, "r") as file:
        logfile_lines = file.read().splitlines()

    # Individua le righe che rappresentano un tentativo di autenticazione fallito
    keyword = "failed"
    logfile_failed_lines = [l for l in logfile_lines if keyword in l.lower()]

    events = []
    for log_line in logfile_failed_lines:
        # estrazione timestamp
        timestamps_found = re.findall(TIMESTAMP_PATTERN, log_line)
        timestamp = "" if not timestamps_found else timestamps_found[0]

        # estrazione IP
        ips_found = re.findall(IP_PATTERN, log_line)
        ip = "" if not ips_found else ips_found[0]

        # estrazione User
        target_users_found = re.findall(USER_PATTERN, log_line)
        target_users = "" if not target_users_found else target_users_found[0]

        event = Event(timestamp, ip, target_users)
        events.append(event)

    # Aggregazione
    ## Conteggio del numero totale di tentativi falliti analizzati.
    num_tot_fails = len(logfile_failed_lines)

    ## Conteggio dei fallimenti per IP sorgente (ordinati dal più frequente al meno frequente).
    ip_failed_counter = Counter(event.ip for event in events)
    num_ip_failed = len({ev.ip for ev in events})

    ## Conteggio dei fallimenti per username (utile per capire se provano utenti standard o nomi specifici).
    user_failed_counter = Counter(event.target_users for event in events)

    ## Tracciare, per ciascun IP, la lista degli utenti provati e l'intervallo temporale (primo e ultimo evento visto).
    #grouped: ip > target_users > lista di timestamp
    grouped_events = {}
    for ev in events:
        if ev.ip not in grouped_events:
            grouped_events[ev.ip] = {}
        if ev.target_users not in grouped_events[ev.ip]:
            grouped_events[ev.ip][ev.target_users] = []
        grouped_events[ev.ip][ev.target_users].append(ev.timestamp)

    ## Triage base: evidenziare gli IP il cui conteggio è >= threshold.
    #ip_with_num_fails_over_threshold = [ip for ip, cnt in ip_failed_counter.items() if cnt > threshold]

    '''
    Output atteso
    In modalità text (a terminale):
        - Riepilogo generale (righe lette, tentativi falliti totali, numero di IP unici).
        - Tabella o elenco ordinato dei Top IP con: IP, Tentativi, Utenti distinti, Flag (es. [ALERT >= 5] o [OK]).
        - Breve lista dei Top Username provati.
    In modalità json: una struttura pulita con metadati (file analizzato, soglia usata) e liste/dizionari per top_ips e top_users, così in futuro potrai riutilizzarla in altri script.
    '''

    if output_format == "text":
        SEP = "=" * 82
        SUB = "-" * 82

        print(SEP)
        print("FAILED AUTHENTICATION ATTEMPTS SUMMARY")
        print(SEP)
        print(f"Analyzed file   : {logfile}")
        print(f"Total lines     : {len(logfile_lines)}")
        print(f"Failed attempts : {num_tot_fails}")
        print(f"Unique source IPs: {num_ip_failed}")
        print(f"Alert threshold : >= {threshold} attempts")

        print("\n" + SUB)
        print("TOP SOURCE IPs")
        print(SUB)
        for ip, cnt in ip_failed_counter.most_common():
            marker = "!!" if cnt >= threshold else "  "
            flag = f"[ALERT >= {threshold}]" if cnt >= threshold else "[OK]"
            print(f"{marker} {ip:<18} {cnt:>6} attempts  {flag}")

        print("\n" + SUB)
        print("TOP TARGET USERNAMES")
        print(SUB)
        for user, cnt in user_failed_counter.most_common():
            print(f"   {user:<15} {cnt:>6} attempts")

        print("\n" + SUB)
        print("TIMELINE DETAIL BY IP")
        print(SUB)
        for ip, cnt in ip_failed_counter.most_common():
            general_flag = f"[ALERT >= {threshold}]" if cnt >= threshold else "[OK]"
            print(f"{ip}  ({cnt} attempts) {general_flag}")
            for user, tms in grouped_events[ip].items():
                num_attempts_per_user = len(tms)
                print(f"   {user:<15} {num_attempts_per_user:>4}x  "
                      f"{tms[0]} -> {tms[-1]}")

    elif output_format == "json":
        print("TBD")


def main():
    #parse input
    parser = argparse.ArgumentParser(description="Riassume un file di log.")
    parser.add_argument("logfile", help="Percorso del file di log da analizzare.") #arg obbligatorio
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Soglia minima di tentativi falliti per segnalare un IP come sospetto/rilevante.")
    parser.add_argument("--format", default=DEFAULT_FORMAT, dest="output_format", help="Formato dell'output a terminale o su file.")

    args = parser.parse_args()

    failed_auth_log_summary(args.logfile, args.threshold, args.output_format)

if __name__ == "__main__":
    main()

