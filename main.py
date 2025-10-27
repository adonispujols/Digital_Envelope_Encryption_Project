# CS 351001
# Project 2: Mini Applied Cryptography Project
# Fall 2025
# Group A Members: Bassil Saleh, Ethan Bunagan, Adonis Pujols, Amulya Prasad, Jonathan Metry

# Operations:
# -g, --generate-keypair
# -e, --encrypt
# -d, --decrypt

# Parameters:
# -m, --message
# -p, --public-key
# -r, --private-key

# Command line usage (with long command names):
# main.py --generate-keypair [keypair_name]
# main.py --encrypt --message message_file --public-key some_public_key --private-key some_private_key
# main.py --decrypt --message message_file --public-key some_public_key --private-key some_private_key
# If keypair_name is omitted, use a default name

# Command line usage (with short command names):
# main.py -g [keypair_name]
# main.py -e -m message_file -p some_public_key -r some_private_key
# main.py -d -m message_file -p some_public_key -r some_private_key
# If keypair_name is omitted, use a default name

import sys
import argparse

DEFAULT_KEYPAIR_NAME = 'my_rsa_key'

def makeArgParser():
	parser = argparse.ArgumentParser(
		description='Generate keypairs, encrypt and decrypt messages'
	)
	parser.add_argument(
		'-g', 
		'--generate-keypair', 
		default=DEFAULT_KEYPAIR_NAME , 
		nargs='?',
		help=f"The name of your RSA key file. Defaults to '{DEFAULT_KEYPAIR_NAME}'."
	)
	parser.add_argument(
		'-e',
		'--encrypt',
		action='store_true',
		help='Used to specify you want to encrypt a message.'
	)
	parser.add_argument(
		'-d',
		'--decrypt',
		action='store_true',
		help='Used to specify you want to decrypt a message.'
	)
	parser.add_argument(
		'-m',
		'--message',
		nargs=1,
		help='The filename of the message you want to encrypt or decrypt.'
	)
	parser.add_argument(
		'-p',
		'--public-key',
		nargs=1,
		help='The filename of your public key.'
	)
	parser.add_argument(
		'-r',
		'--private-key',
		nargs=1,
		help='The filename of your private key.'
	)
	return parser

def main():
	cmdParser = makeArgParser()
	cmdParser.print_help()

if __name__ == "__main__":
	main()
