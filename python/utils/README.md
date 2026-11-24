# Generatore di Passphrase

Script Python che genera passphrase combinando parole casuali prese da un file dizionario.

## Come funziona

Lo script legge un elenco di parole da un file di testo (una parola per riga), ne estrae a caso un certo numero e le unisce con il separatore scelto, applicando la trasformazione di maiuscole/minuscole desiderata.

## Requisiti

- Python >= 3.6
- Un file dizionario con una parola per riga (`dictionary.txt` di default)

## Uso da terminale

```
python generatore_passphrase.py
# casa gatto sole libro scala

python generatore_passphrase.py --word_count 4 --separator "-" --case t
# Casa-Gatto-Sole-Libra

python generatore_passphrase.py --word_count 6 --case m --separator "_"
# gatto_SOLE_libro_CASA_scala_Porta
```

Visualizza l'aiuto con tutti i parametri:

```
python generatore_passphrase.py --help
```

## Parametri

| Parametro | Default | Descrizione |
| --- | --- | --- |
| `--word_count` | `5` | Numero di parole nella passphrase (deve essere > 0) |
| `--separator` | `' '` (spazio) | Separatore tra le parole |
| `--case` | `l` | Trasformazione di case (vedi sotto) |
| `--dictionary_file` | `dictionary.txt` | Percorso del file dizionario |

### Opzioni per `--case`

| Valore | Effetto | Esempio |
| --- | --- | --- |
| `l` | minuscolo (lowercase) | `gatto cane topo` |
| `u` | MAIUSCOLO (uppercase) | `GATTO CANE TOPO` |
| `t` | Prima Lettera Maiuscola (title) | `Gatto Cane Topo` |
| `m` | maiuscole/minuscole casuali per parola (mixed) | `GATTO CANE topo`, o `gatto CANE topo` etc. |

## Uso come modulo

Il modulo espone la funzione `genera_passphrase()` riutilizzabile da altri script:

```python
from generatore_passphrase import genera_passphrase

p = genera_passphrase(word_count=4, case="t", separator="-")
print(p)
```

## Struttura del codice

- `genera_passphrase(...)` — logica principale, solleva `ValueError` per parametri non validi
- `main()` — parsing degli argomenti da terminale e stampa del risultato

## Creare un dizionario

Puoi usare qualsiasi lista di parole, una per riga. Ad esempio:

```
casa
gatto
sole
libro
topo
scala
porta
cane
```

## Modulo random

Per la scelta randomica delle parole del dizionario viene usato il modulo [`secrets`](https://docs.python.org/3/library/secrets.html).
