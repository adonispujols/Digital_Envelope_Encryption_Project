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
# -n, --new-keypair-name
# -p, --public-key
# -r, --private-key

# Command line usage (with short command names):
# main.py -g [-n keypair_name]
# main.py -e -m message_file -p some_public_key -r some_private_key
# main.py -d -m message_file -p some_public_key -r some_private_key
# If keypair_name is omitted, use a default name

import argparse
import sys

DEFAULT_KEYPAIR_NAME = 'my_rsa_key'

def makeArgParser():
	parser = argparse.ArgumentParser(
		description='Generate keypairs, encrypt and decrypt messages'
	)
	parser.add_argument(
		'-g', 
		'--generate-keypair', 
		action='store_true',
		help="Used to specify you want to generate a keypair (public and private key)."
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
		'-n',
		'--new-keypair-name',
		nargs='?',
		default=DEFAULT_KEYPAIR_NAME,
		help=f"The name of your keypair files. Defaults to {DEFAULT_KEYPAIR_NAME}."
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
	args = cmdParser.parse_args()
#	print(args)
	if args.generate_keypair:
		if args.new_keypair_name is None:
			print("When using the option '-n' or '--new-keypair-name', you must specify a name for your key file.")
			sys.exit(1)
		print('Generate a keypair.')
		print(f"New keypair name: {args.new_keypair_name}")
	elif args.encrypt:
		if args.message is None:
			print('Missing argument: -m MESSAGE (or --message MESSAGE)')
			print('Where MESSAGE is the file name of your message.')
			sys.exit(1)
		print('Encrypt a message.')
		print(f"Message file name: {args.message[0]}")
	elif args.decrypt:
		if args.message is None:
			print('Missing argument: -m MESSAGE (or --message MESSAGE)')
			print('Where MESSAGE is the file name of your message.')
			sys.exit(1)
		print('Decrypt a message.')
		print(f"Message file name: {args.message[0]}")
	else:
		sys.exit(1)
		pass

if __name__ == "__main__":
	main()
