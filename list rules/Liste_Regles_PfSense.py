#!/usr/bin/python
try:
	import requests
except:
	print("Cette action requiert la bibliotheque requests de Python. Veuillez l'installer par l'action Installer_Paquet_Python")
	exit(1)
import re
import sys
try:
	from bs4 import BeautifulSoup
except:
	print("Cette action requiert la bibliotheque bs4 de Python. Veuillez l'installer par l'action Installer_Paquet_Python")
	exit(1)

def usage():
	print("Usage: ./Liste_Regle_PfSense <adresse IP> <login> <mot de passe> <interface>")
if len(sys.argv) != 5:
	usage()
	exit(1)

# Ou se trouve la page web de PfSense
routeur = "https://" + sys.argv[1]
login = sys.argv[2]
mdp = sys.argv[3]
# Interface dont on veut voir les regles
iface = sys.argv[4]

class Regle:
	def __init__(self, rid, action, protocol, source, src_port, destination, dest_port, description):
		self.rid = rid
		self.action = action
		self.protocol = protocol
		self.source = source
		self.src_port = src_port
		self.destination = destination
		self.dest_port = dest_port
		self.description = description
	def affiche(self):
		print(str(self.rid) + "\t\t" + str(self.action) + "\t\t" + self.protocol + "\t\t" + self.source + "\t\t" + self.src_port + "\t\t" + self.destination + "\t\t" + self.dest_port + "\t\t" + self.description)

liste_regles = []
s = requests.Session()

# C'est par ce .php que PfSense affiche les regles
# Il prend un parametre: if=<L'interface choisie>
lien = routeur + "/firewall_rules.php"
index = routeur + "/index.php"

# Authentification
auth_data = {"__csrf_magic": "",
	"usernamefld": login,
	"passwordfld": mdp,
	"login": "Sign In"}
r = s.get(routeur,verify=False)
# On cherche le token anti-CSRF
csrf = re.findall('__csrf_magic\' value=\"(.*?)\"', r.text)
auth_data["__csrf_magic"] = csrf
s.post(index, data=auth_data, verify=False)

# Obtenir le contenu de la page
data = {"if": iface}
page = s.get(lien, params=data, verify=False)
soup = BeautifulSoup(page.text, 'html.parser')

# La page est organisée comme un tableau
# Les lignes qui affichent les règles sont contenues entre le tag <tr>
regles = soup.find_all("tr")
for regle in regles:
	# Dans chaque ligne, les info sont tenues entre les tags <td>
	liste_td = regle.find_all("td")
	if len(liste_td) > 0:
		# Il faut retoucher les strings pour avoir le bon contenu
		rid = re.findall('value=\"(.*)\"', str(liste_td[0]))
		action = re.findall('traffic is (.*?)\"', str(liste_td[1]))
		protocol = str(liste_td[3]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		source = str(liste_td[4]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		src_port = str(liste_td[5]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		destination = str(liste_td[6]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		dest_port = str(liste_td[7]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		description = str(liste_td[11]).replace("\t","").replace("\n","").replace("<td>","").replace("</td>","")
		nouvelle_regle = Regle(rid, action, protocol, source, src_port, destination, dest_port, description)
		liste_regles.append(nouvelle_regle)

print('ID\t\tAction\t\tProtocol\t\tSource\t\tSrc_port\t\tDestination\t\tDest_port\t\tDescription')
for regle in liste_regles:
	regle.affiche()

# Se deconnecter
s.get(index,params={"logout": "yes"})
