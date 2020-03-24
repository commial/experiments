# From https://github.com/mindcrypt/uriDeep
source = open("uriDeep/data/deepDiccConfusables.txt")

confusables = {line[0]: list(line.rstrip()[1:]) for line in source}

# Remove some of them (too much FP)
confusables["t"].remove("i")
confusables["o"].remove("0")
confusables["0"].remove("o")
confusables["1"].remove("l")
confusables["l"].remove("1")
confusables["u"].append("ü")
confusables["o"].append("ö")
confusables["u"].append("û")
confusables["o"].append("ô")

# AFNIC specific
confusables["a"] += ["à", "á", "â", "ã", "ä", "å", "æ"]
confusables["c"] += ["ç"]
confusables["e"] += ["è", "é", "ê", "ë"]
confusables["i"] += ["ì", "í", "î", "ï"]
confusables["n"] += ["ñ"]
confusables["o"] += ["ò", "ó", "ô", "õ", "ö"]
confusables["u"] += ["ù", "ú", "û", "ü"]
confusables["y"] += ["ý", "ÿ"]

rev_confusables = {}
for key, values in confusables.items():
    for value in values:
        rev_confusables[value] = key
    rev_confusables[key] = key

# From Alexa top 1M
alexa_1m = open("top-1m.csv")
alexa = []
for line in alexa_1m:
    line = line.strip().split(",", 1)[1]
    alexa.append(line)

# domains_uniq.txt obtained from CN / SAN extraction of Certificate Transparency List
#
# Sources (corresponding to the 2020/03/22):
# - Google 'Argon2020', ~ 10%
# - DigiCert Log Server, full
# - DigiCert Log Server 2, full
# - Cloudflare 'Nimbus2020' Log, full
# - Cloudflare 'Nimbus2021' Log, full
# - Cloudflare 'Nimbus2022' Log, full
# - Cloudflare 'Nimbus2023' Log, full
# - Let's Encrypt 'Oak2020' log, full
# - Let's Encrypt 'Oak2021' log, full
# - Let's Encrypt 'Oak2022' log, full

for i, domain in enumerate(open("domains_uniq.txt")):
    # Verbose output
    if (i % 10000000 == 0):
        print("Current: %d" % i)
    # Dummy filtering of IDN domains
    if not "xn--" in domain:
        continue
    try:
        decoded = domain.rstrip().encode("ascii").decode("idna")
    except UnicodeError:
        print("[WARNING] Skip %s" % domain.rstrip())

    unconfuse = ""
    found = True
    for c in decoded:
        if c in [".", "-"]:
            unconfuse += c
            continue
        orig = rev_confusables.get(c, None)
        if orig is None:
            found = False
            break
        unconfuse += orig
    if not found:
        continue
    if unconfuse not in alexa:
        continue
    print("%s (%s - https://%s)" % (unconfuse, decoded, domain.rstrip()))
