#!/bin/sh

green=`tput setaf 34`
purple=`tput setaf 8`
red=`tput setaf 9`
blue=`tput setaf 21`

echo "${blue}[*] Updating apt..."
tput sgr0
sudo apt update 
if [ $? -eq 0 ]; then
	echo "${green}[*] Apt updated successfully."
	echo "${blue}[*] Updating apt-get..."
	tput sgr0
	sudo apt-get update
	if [ $? -eq 0 ]; then
		echo "${green}[*] apt-get updated successfully"
		echo "${blue}[*] Installing python3..."
		tput sgr0
		sudo apt-get install python3
		if [ $? -eq 0 ]; then
			echo "${green}[*] Python3 installed successfully"
			echo "${blue}[*] Installing python3-pip..."
			tput sgr0
			sudo apt-get install python3-pip
			if [ $? -eq 0 ]; then
				echo "${green}[*] Python3-pip installed successfully"
				echo "${blue}[*] Installing scapy..."
				tput sgr0
				sudo pip3 install scapy
				if [ $? -eq 0 ]; then
					echo "${green}[*] scapy installed successfully"
					echo "${blue}[*] Installing getmac..."
					tput sgr0
					sudo pip3 install getmac
					if [ $? -eq 0 ]; then
						echo "${green}[*] getmac installed successfully"
						echo "${blue}[*] Installing netifaces..."
						tput sgr0
						sudo pip3 install netifaces
						if [ $? -eq 0 ]; then
							echo "${green}[*] netifaces installed successfully"
							echo "${green}[*] All necessary prerequisites have been installed successfully! You can now run arp_pam.py."
							echo "${blue}[*] To run the tool, write"
							echo "${purple}python3 arp_pam.py"
						else
							echo "${red}[!] Could not install netifaces"
						fi
					else
						echo "${red}[!] Could not install getmac"
					fi
				else
					echo "${red}[!] Could not install scapy"
				fi
			else
				echo "${red}[!] Could not install python3-pip"
			fi
		else
			echo "${red}[!] Could not install python3"
		fi
	else
		echo "${red}[!] Could not update apt-get"
	fi
else
	echo "${red}[!] Could not update apt"
fi
tput sgr0
