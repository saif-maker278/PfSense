#!/usr/bin/python
import re
import sys
import requests



# Ceci est pour eliminer les avertissements de HTTPS
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def usage():
	print("Usage ./Ajouter_Regle_PfSense.py <login> <mot de passe> <adresse web de PfSense> <action> <interface> <Famille d'IP> <protocol> <type d'ICMP> <IP source> <port source> <IP destination> <port destination> <description>")
if len(sys.argv) < 13 or len(sys.argv) > 14:
	usage()
	exit(1)
 

login = sys.argv[1]
mdp = sys.argv[2]
# Ou se trouve la page web de PfSense
adresse_web = "https://" + sys.argv[3]
action = str(sys.argv[4]).lower()
interface = str(sys.argv[5]).lower()
famille_ip = str(sys.argv[6]).lower()
protocol = str(sys.argv[7]).lower()
type_icmp = str(sys.argv[8]).lower()
ip_src = sys.argv[9]
port_src = sys.argv[10]
ip_dst = sys.argv[11]
port_dst = sys.argv[12]
description = sys.argv[13] if len(sys.argv) == 14 else ""

# Le template de données à renvoyer par POST
# Certains champs sont à supprimer pour certaines options de protocol ou type de source/destination
data = {"__csrf_magic":"",
	"type": "",
	"interface": "",
	"ipprotocol": "",
	"proto": "",
	"icmptype%5B%5D": "any",
	"srctype": "",
	"src": "",
	"srcmask": "",
	"srcbeginport": "",
	"srcbeginport_cust": "",
	"srcendport": "",
	"srcendport_cust": "",
	"dsttype": "",
	"dst": "",
	"dstmask": "",
	"dstbeginport": "",
	"dstbeginport_cust": "",
	"dstendport": "",
	"dstendport_cust": "",
	"descr": "",
	"save": "Save"
}

# Check si l'argument est une interface
# Pour PfSense, a la base il y a 2 interfaces qui sont wan et lan
# Après on pourrait en avoir d'autres, qui seraient nommées opt1, opt2,...
def est_interface(src):
	if src in ["wan", "lan"]:
		return src
	pattern = re.compile("^opt([1-9]|[1-9][0-9]+)$")
	if pattern.match(src):
		return src
	return False
def est_ip(ip):
	pattern_ip = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
	if pattern_ip.match(ip):
		return ip
	else:
		return False
# Un réseau est définit sous la norme CIDR
# Retourner l'adresse et le masque
def est_reseau(cidr):
	pattern_cidr = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([1-9]|[1-2][0-9]|3[0-2])$")
	if pattern_cidr.match(cidr):
		return [str(cidr).split("/")[0], str(cidr).split("/")[1]]
	else:
		return False
# Pour le port, l'argument valide peut être:
# Un seul port
# Ou une intervalle de ports, avec:
# :1000 pour ceux inferieurs a 1000 inclu
# 2000:3000 pour ceux entre 2000 inclu et 3000 inclu
# 4000: pour ceux superieurs a 4000 inclu
def est_port(port):
	if port == "any":
		return port
	pattern_1 = re.compile("^[0-9]+$")
	pattern_range = re.compile("^([0-9]+):([0-9]+)$")
	pattern_range_1 = re.compile("^([0-9]+):$")
	pattern_range_2 = re.compile("^:([0-9]+)$")
	if pattern_1.match(port) and int(port) < 65536:
		return [port, port]
	if pattern_range.match(port) and int(port.split(":")[0]) <= int(port.split(":")[1]) and int(port.split(":")[1]) <= 65535:
		return [port.split(":")[0], port.split(":")[1]]
	if pattern_range_1.match(port) and int(port.split(":")[0]) <= 65535:
		return [port.split(":")[0], "65535"]
	if pattern_range_2.match(port) and int(port.split(":")[1]) <= 65535:
		return ["0", port.split(":")[1]]
	print("Argument port est invalide")
	exit(1)

# Pour le protococl ICMP, on peut choisir le type, entre Echo Request, Echo Reply, Parameters Problem, Router Advertisement, Router Solicitation, Time Exceeded et Destination Unreachable
def mettre_icmptype(icmp):
	if icmp in ["any", "echorep", "echoreq", "paramprob", "redir", "routeradv", "routersol", "timex", "unreach"]:
		data["icmptype%5B%5D"] = icmp
		return
	else:
		print("Argument type d'ICMP est invalide")
		exit(1)
def mettre_src_port(port):
	if est_port(port) == "any":
		data["srcbeginport"] = "any"
		data["srcendport"] = "any"
		data.pop("srcbeginport_cust")
		data.pop("srcendport_cust")
		return
	else:
		data["srcbeginport_cust"] = est_port(port)[0]
		data["srcendport_cust"] = est_port(port)[1]
		data.pop("srcbeginport")
		data.pop("srcendport")
def mettre_dst_port(port):
	if est_port(port) == "any":
		data["dstbeginport"] = "any"
		data["dstendport"] = "any"
		data.pop("dstbeginport_cust")
		data.pop("dstendport_cust")
		return
	else:
		data["dstbeginport_cust"] = est_port(port)[0]
		data["dstendport_cust"] = est_port(port)[1]
		data.pop("dstbeginport")
		data.pop("dstendport")
def mettre_src_type(src):
	if src == "any":
		data["srctype"] = "any"
		data.pop("src")
		data.pop("srcmask")
		return
	if est_ip(src):
		data["srctype"] = "single"
		data["src"] = est_ip(src)
		data.pop("srcmask")
		return
	if est_reseau(src):
		data["srctype"] = "network"
		data["src"] = est_reseau(src)[0]
		data["srcmask"] = est_reseau(src)[1]
		return
	if est_interface(src):
		data.pop("src")
		data.pop("srcmask")
		data["srctype"] = est_interface(src)
		return
	print("Argument source est invalide")
	exit(1)
def mettre_dst_type(dst):
	if dst == "any":
		data["dsttype"] = "any"
		data.pop("dst")
		data.pop("dstmask")
		return
	if est_ip(dst):
		data["dsttype"] = "single"
		data["dst"] = est_ip(dst)
		data.pop("dstmask")
		return
	if est_reseau(dst):
		data["dsttype"] = "network"
		data["dst"] = est_reseau(dst)[0]
		data["dstmask"] = est_reseau(dst)[1]
		return
	if est_interface(dst):
		data["dsttype"] = est_interface(dst)
		data.pop("dst")
		data.pop("dstmask")
		return
	print("Argument destination est invalide")
	exit(1)
def enlever_src_ports():
	data.pop("srcbeginport")
	data.pop("srcendport")
	data.pop("srcbeginport_cust")
	data.pop("srcendport_cust")
def enlever_dst_ports():
	data.pop("dstbeginport")
	data.pop("dstendport")
	data.pop("dstbeginport_cust")
	data.pop("dstendport_cust")
def mettre_type(action):
	if action in ["pass", "block", "reject"]:
		data["type"] = action
		return
	else:
		print("Argument action est invalide")
		exit(1)
def mettre_interface(interface):
	if est_interface(interface):
		data["interface"] = interface
		return
	else:
		print("Argument interface est invalide")
		exit(1)
def mettre_ipprotocol(inet):
	if inet == "ipv4":
		data["ipprotocol"] = "inet"
		return
	if inet == "ipv6":
		data["ipprotocol"] = "inet6"
		return
	if inet == "ipv4/ipv6":
		data["ipprotocol"] = "inet46"
		return
	print("Argument famille ip est invalide")
	exit(1)
def mettre_proto(protocol):
	if protocol == "any":
		data["proto"] = "any"
		mettre_src_type(ip_src)
		enlever_src_ports()
		mettre_dst_type(ip_dst)
		enlever_dst_ports()
		return
	if protocol == "icmp":
		data["proto"] = protocol
		mettre_icmptype(type_icmp)
		mettre_src_type(ip_src)
		enlever_src_ports()
		mettre_dst_type(ip_dst)
		enlever_dst_ports()
		return
	if protocol in ["tcp", "udp"]:
		data["proto"] = protocol
		mettre_src_type(ip_src)
		mettre_src_port(port_src)
		mettre_dst_type(ip_dst)
		mettre_dst_port(port_dst)
		return
	if protocol == "tcp/udp":
		data["proto"] = r"tcp%2Fudp"
		mettre_src_type(ip_src)
		mettre_src_port(port_src)
		mettre_dst_type(ip_dst)
		mettre_dst_port(port_dst)

	else:
		print("Argument protocol est invalide")
		exit(1)
def mettre_description(desc):
	data["descr"] = desc

s = requests.Session()

# Recuperer le token anti-csrf dans un site
def chercher_csrf_token(lien):
	r = s.get(lien, verify=False)
	csrf = re.search('__csrf_magic\' value=\"(.*?)\"', r.text)
	if csrf:
		return csrf.group(1)
	else:
		print("Token anti-csrf non trouve. L'adresse web de PfSense est bien saisie?")
		exit(1)

# C'est par ce .php que PfSense modifie ses regles
# Il prend un paramètre: if=<L'interface choisie>
page_modif_regles = adresse_web + "/firewall_rules_edit.php?if=" + interface
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
# Forger les données a partir des arguments
data["__csrf_magic"] = chercher_csrf_token(page_modif_regles)
mettre_type(action)
mettre_interface(interface)
mettre_ipprotocol(famille_ip)
mettre_proto(protocol)
mettre_description(description)
print(data)

print("Ajout de la nouvelle regle...")
# Ajouter une nouvelle règle avec les données ci-dessus
s.post(page_modif_regles, data=data, verify=False)

print("Appliquer...")
# Il y a un bouton "Apply Change" qui apparait, on clique sur ce bouton
appliquer = {"__csrf_magic": chercher_csrf_token(page_regles),
	"apply": "Apply Change"	
}
s.post(page_regles, data=appliquer, verify=False)

print("Deconnexion...")
# Se déconnecter
s.get(index,params={"logout": "yes"})
