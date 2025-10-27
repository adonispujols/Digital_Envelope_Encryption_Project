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

import argparse, sys, os

DEFAULT_KEYPAIR_NAME = 'my_rsa_key'

def make_arg_parser():
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
	cmd_parser = make_arg_parser()
	args = cmd_parser.parse_args()
	# print(args)
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
		if args.public_key is None:
			print('Missing argument: -p PUBLIC_KEY (or --public-key PUBLIC_KEY)')
			print('Where PUBLIC_KEY is your public key file.')
			sys.exit(1)
		if args.private_key is None:
			print('Missing argument: -r PRIVATE_KEY (or --private-key PRIVATE_KEY)')
			print('Where PRIVATE_KEY is your private key file.')
			sys.exit(1)
		print('Encrypt a message.')
		print(f"Message file name: {args.message[0]}")
		# Check if the file path exists
		if not os.path.exists(args.message[0]):
			print(f"Error: {args.message[0]} not found.")
			sys.exit(1)
		# Make sure it's a file and not something else like a directory
		if not os.path.isfile(args.message[0]):
			print(f"Error: {args.message[0]} is not a file.")
			sys.exit(1)
		# Open the file and read its contents
		print(f"Opening {args.message[0]} ...")
		with open(args.message[0]) as message_file:
			message_contents = message_file.read()
		print(f"Contents of {args.message[0]}:")
		print(message_contents)
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
