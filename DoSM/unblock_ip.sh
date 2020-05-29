#!/bin/bash

blue=`tput setaf 21`
green=`tput setaf 34`
red=`tput setaf 9`

print_help()
{
	echo "This tool is used to unblock IP addresses that were blackholed."
	echo "	-h: Displays help."
	echo "	-a: Remove all IP addresses from blackhole list."
	echo "* If neither of these options are used, the help menu (this menu) will be displayed."
	echo "* If you'd like to unblock a certain IP address, simply pass said IP address as a parameter when calling this tool. You may also pass multiple IP addresses."
}

if [ "$#" -eq 0 ]; then
	print_help
else
	if [ $1 == "-h" ]; then
		print_help
	fi
	if [ "$1" == "-a" ]; then
		ip route | grep 'blackhole' | while read -r line; do
		vars=( $line )
		ip route del "${vars[1]}"
	done
	fi
fi
tput sgr0
