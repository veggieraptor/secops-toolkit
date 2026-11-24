import argparse
import secrets

'''
input:
    word_count: integer (default = 5)
    separator: string (default ' ')
    case: string (defaul 'l')
        l   lowercase
        U,u uppercase
        t   title (For Example Like This)
        m   mixed (l and U randomly, for EXAMPLE LIKE this)
    dictionary_file: string (default 'dictionary.txt)

output:
    passphrase: string
'''

DEFAULT_word_count = 5
DEFAULT_separator = ' '
DEFAULT_case = 'l'
DEFAULT_file = 'dictionary.txt'


def genera_passphrase(word_count=DEFAULT_word_count, separator=DEFAULT_separator, case=DEFAULT_case, dictionary_file=DEFAULT_file):

    # validate input
    if word_count <= 0:
        parser.error("word_count dev'essere > 0")

    if case == 'l':
        metodo_case = lambda x: x.lower()
    elif case == 'u' or case == 'U':
        metodo_case = lambda x: x.upper()
    elif case == 't':
        metodo_case = lambda x: x.capitalize()
    elif case == 'm':
        metodo_case = lambda x: secrets.choice([x.lower(), x.upper()])
    else:
        parser.error("case non valido")

    # open dictionary_file
    with open (dictionary_file, "r") as file:
        dictionary = file.read().splitlines()


    #genero passphrase
    words = []
    for i in range(word_count):
        word  = secrets.choice(dictionary)
        words.append(metodo_case(word))

    return separator.join(words)


def main():
    #parse input
    #TODO migliora documentazione
    parser = argparse.ArgumentParser(description="Generate a passphrase.")
    parser.add_argument("--word_count", type=int, default=DEFAULT_word_count, help="Numero delle parole della passphrase.")
    parser.add_argument("--separator", default=DEFAULT_separator, help="Separatore delle parole nella passphrase.")
    parser.add_argument("--case", default=DEFAULT_case, help="Case delle parole della passphrase")
    parser.add_argument("--dictionary_file", default=DEFAULT_file, help="File dizionario scelto")

    args = parser.parse_args()

    passphrase = genera_passphrase(args.word_count, args.separator, args.case, args.dictionary_file)

    print(f"Generatore passphrase (word_count:{args.word_count}, separator:'{args.separator}', case:{args.case}, dictionary_file:{args.dictionary_file})\n")

    print(passphrase)


if __name__ == "__main__":
    main()






