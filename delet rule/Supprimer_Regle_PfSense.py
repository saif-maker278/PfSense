#!/usr/bin/python
try:
	import requests
except:
	print("Cette action requiert la bibliotheque requests de Python. Veuillez l'installer par l'action Installer_Paquet_Python")
	exit(1)
import re
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def usage():
	print("Usage ./Supprimer_Regle_PfSense.py <login> <mot de passe> <adresse web de PfSense> <interface> <id>")
if len(sys.argv) != 6:
	usage()
	exit(1)

login = sys.argv[1]
mdp = sys.argv[2]
# Ou se trouve la page web de PfSense
adresse_web = "https://" + sys.argv[3]
interface = str(sys.argv[4]).lower()
id_regle = sys.argv[5]

def est_interface(src):
	if src in ["wan", "lan"]:
		return src
	pattern = re.compile("^opt([1-9]|[1-9][0-9]+)$")
	if pattern.match(src):
		return src
	return False

if not est_interface(interface):
	print("Argument interface est invalide")
	exit(1)

s = requests.Session()

# Récupérer le token anti-csrf dans un site
def chercher_csrf_token(lien):
	r = s.get(lien, verify=False)
	csrf = re.search('__csrf_magic\' value=\"(.*?)\"', r.text)
	if csrf:
		return csrf.group(1)
	else:
		print("Token anti-csrf non trouve. L'adresse web de PfSense est bien saisie?")
		exit(1)

# C'est par ce .php que PfSense modifie ses règles
# Il prend un paramètre: if=<L'interface choisie>
page_regles = adresse_web + "/firewall_rules.php?if=" + interface
index = adresse_web + "/index.php"


# Authentification
print("Authentification...")
auth_data = {"__csrf_magic": chercher_csrf_token(index),
	"usernamefld": login,
	"passwordfld": mdp,
	"login": "Sign In"}
s.post(index, data=auth_data, verify=False)

print("Forger les parametres...")
# Forger les données à partir des arguments
data = {"act": "del",
	"if": interface,
	"id": id_regle,
	"__csrf_magic": ""
}
data["__csrf_magic"] = chercher_csrf_token(page_regles)

print("Suppression de la regle avec id = " + id_regle)
# Supprimer la règle avec id donné
s.post(page_regles, data=data, verify=False)

print("Appliquer...")
# Il y a un bouton "Apply Change" qui apparait, on clique sur ce bouton
appliquer = {"__csrf_magic": chercher_csrf_token(page_regles),
	"apply": "Apply Change"	
}
s.post(page_regles, data=appliquer, verify=False)

print("Deconnexion...")
# Se déconnecter
s.get(index, params={"logout": "yes"})
