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
	''' Define the command line arguments of this program and how it should accept parameters. '''
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

def is_a_normal_file(file_path):
	''' For command line options that expect an argument, check if the argument actually exists and if it's a normal file. '''
	return os.path.exists(file_path) and os.path.isfile(file_path)

def validate_args(args, parser):
	''' Used to check if the user's options make sense, and if the files they passed actually exist. '''
	if args.generate_keypair:
		if args.new_keypair_name is None:
			print("When using the option '-n' or '--new-keypair-name', you must specify a name for your key file.")
			sys.exit(1)
		print('Generate a keypair.')
		print(f"New keypair name: {args.new_keypair_name}")
	elif args.encrypt or args.decrypt:
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
		if not is_a_normal_file(args.message[0]):
			print(f"Error: {args.message[0]} either cannot be found or is not a normal file.")
			sys.exit(1)
		if not is_a_normal_file(args.public_key[0]):
			print(f"Error: {args.public_key[0]} either cannot be found or is not a normal file.")
			sys.exit(1)
		if not is_a_normal_file(args.private_key[0]):
			print(f"Error: {args.private_key[0]} either cannot be found or is not a normal file.")
			sys.exit(1)
		print(f"{'Encrypt' if args.encrypt else 'Decrypt'} a message.")
		print(f"Message file name: {args.message[0]}")
		print(f"Public key file name: {args.public_key}")
		print(f"Private key file name: {args.private_key}")
	else:
		print("No options specified. Here's some help:")
		parser.print_help()
		sys.exit(1)

def main():
	cmd_parser = make_arg_parser()
	args = cmd_parser.parse_args()
	# print(args)
	validate_args(args, cmd_parser)

if __name__ == "__main__":
	main()
