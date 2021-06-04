#!/bin/bash
if ! command -v expect &>/dev/null; then
	echo "Ce script requiert le paquet expect"
	exit 1
fi
if [ $# -ne  3 ]; then
	echo "Usage: ./Liste_Interface_PfSense.sh <adresse de PfSense> <identifiant ssh> <mot de passe ssh>"
else
	fichier=/tmp/banner.txt
	export PFSENSE_MDP=$3
	export PFSENSE_SSH=$2@$1
	(/usr/bin/expect <<EOF
set pfsense "\$env(PFSENSE_SSH)"
set mdp "\$env(PFSENSE_MDP)"
spawn ssh -o StrictHostKeyChecking=no \$pfsense
expect "assword"
send "\$mdp\r"
expect "Enter an option:"
send "0\r"
EOF
) > $fichier
	echo "<Surnom> (<vrai nom pour PfSense>)"
	cat $fichier |sed '/^ [0-9]/d' |sed '$d' |sed '1,6d'
	rm $fichier
	unset PFSENSE_MDP
	unset PFSENSE_SSH
fi

