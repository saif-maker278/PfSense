#!/bin/bash
# Ce script ajoute une règle à PfSense par SSH puis par l'outil EasyRule
if ! command -v expect &>/dev/null; then
	echo "Ce script requiert le paquet expect"
	exit 1
fi
if [[ $# -ne  9 ]]; then
	echo "Usage: ./Ajouter_Regle_PfSense_EasyRule.sh <adresse IP de PfSense> <identifiant ssh> <mot de passe ssh> <action> <interface> <protocol> <IP source> <IP destination> <port destination>"
else
	adresse=$1
	ident=$2
	mdp=$3
	action=$4
	interface=$5
	protocol=$6
	source=$7
	desti=$8
	port=$9
	commande=""
	# Action block et unblock demandent seulement l'interface et la source
	if [[ $action == "block" || $action == "unblock" ]]; then
		commande="easyrule $action $interface $source"
	elif [[ $action == "pass" ]]; then
		commande="easyrule $action $interface $protocol $source $desti $port"
	else
		echo "Argument action est invalide"
		exit 1
	fi
# On doit exporter ces variables en environnement
# Car export n'est pas le même shell que bash
	export PFSENSE_IDENT="$ident"
	export PFSENSE_SSH="$ident@$adresse"
	export PFSENSE_MDP=$mdp
	export COMMANDE=$commande
# Le prossesus est de se connecter par SSH à PfSense, entrer le mot de passe,
# puis choisir 8 pour ouvrir un shell, exécuter la commande EasyRule, quitter le shell et se déconnecter
/usr/bin/expect <<EOF
set identifiant "\$env(PFSENSE_IDENT)"
set pfsense "\$env(PFSENSE_SSH)"
set mdp "\$env(PFSENSE_MDP)"
set cmd "\$env(COMMANDE)"
log_user 0
spawn ssh -o StrictHostKeyChecking=no \$pfsense
expect "assword"
send "\$mdp\r"
expect "Enter an option: "
send "8\r"
expect "\$identifiant"
log_user 1
send "\$cmd\r"
expect "\r"
expect "\$identifiant"
log_user 0
send "exit\r"
expect "Enter an option: "
send "0\r"
expect eof
EOF
	unset PFSENSE_IDENT
	unset PFSENSE_MDP
	unset PFSENSE_SSH
	unset COMMANDE
fi

