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
# -s, --symmetric-key (the symmetric key used for encryption/decryption)
# -i, --signature

# Command line usage (with short command names):
# main.py -g [-n keypair_name]
# main.py -e -m message_file -p some_public_key -r some_private_key
# main.py -d -m message_file -p some_public_key -r some_private_key -s symmetric_key -i signature
# If keypair_name is omitted, use a default name

import argparse, sys, os
from crypto_functions import *

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
	parser.add_argument(
		'-s',
		'--symmetric-key',
		nargs=1,
		help='The filename of the symmetric key used to decrypt your message.'
	)
	parser.add_argument(
		'-i',
		'--signature',
		nargs=1,
		help='The filename of the signature which the message was signed with.'
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
		if args.decrypt and args.symmetric_key is None:
			print('Missing argument: -s SYMMETRIC_KEY (or --symmetric-key SYMMETRIC_KEY)')
			print('Where SYMMETRIC_KEY is your symmetric key file')
			print('(the key used to encrypt/decrypt your message).')
			sys.exit(1)
		if args.decrypt and args.signature is None:
			print('Missing argument: -i SIGNATURE (or --signature SIGNATURE)')
			print('Where SIGNATURE is the signature file.')
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
		if args.decrypt and args.symmetric_key and not is_a_normal_file(args.symmetric_key[0]):
			print(f"Error: {args.symmetric_key[0]} either cannot be found or is not a normal file.")
			sys.exit(1)
		if args.decrypt and args.signature and not is_a_normal_file(args.signature[0]):
			print(f"Error: {args.signature[0]} either cannot be found or is not a normal file.")
			sys.exit(1)
	else:
		print("No options specified. Here's some help:")
		parser.print_help()
		sys.exit(1)

def main():
	cmd_parser = make_arg_parser()
	args = cmd_parser.parse_args()
	# print(args)
	validate_args(args, cmd_parser)
	if args.generate_keypair:
		print('Generating a new keypair...')
		try:
			# Generate new public and private keys
			private_key, public_key = generate_key_pair()
			private_key_pem = serialize_private_key(private_key)
			public_key_pem = serialize_public_key(public_key)
			# Write them to files
			public_key_filename = f"{args.new_keypair_name}.pub"
			private_key_filename = f"{args.new_keypair_name}"
			with open(public_key_filename, "wb") as public_key_file:
				public_key_file.write(public_key_pem)
			with open(private_key_filename, "wb") as private_key_file:
				private_key_file.write(private_key_pem)
		except:
			print("Error occured while creating public/private keypair.")
			sys.exit(1)
		print("Done. Here's your new keys:")
		print(f"New public key name: {public_key_filename}")
		print(f"New private key name: {private_key_filename}")
	elif args.encrypt:
		print('Encrypting message...')
		#=================================================
		# Requires AES encryption to be done by groupmates
		#=================================================
		try:
			print('Reading message...')
			with open(args.message[0], 'rb') as message_file:
				message_bytes = message_file.read()
			print('Reading public & private keys...')
			with open(args.public_key[0], 'rb') as public_key_file:
				public_key_bytes = public_key_file.read()
			with open(args.private_key[0], 'rb') as private_key_file:
				private_key_bytes = private_key_file.read()
		except:
			print("Error occured while opening/reading supplied files.")
			sys.exit(1)
		try:
			print('Converting public/private keys out of PEM format...')
			public_key = deserialize_public_key(public_key_bytes)
			private_key = deserialize_private_key(private_key_bytes)
		except Exception as e:
			print(e)
			print("Error occured while converting public/private keys.")
			sys.exit(1)
		try:
			print('Generating new symmetric key...')
			symmetric_key = generate_aes_key()
		except:
			print("Error occured while generating symmetric key.")
			sys.exit(1)
		# Encrypt the message using the symmetric key
		try:
			print('Encrypting message...')
			ciphertext = encrypt_message_aes(message_bytes, symmetric_key)
		except:
			print("Error occured while encrypting message.")
			sys.exit(1)
		# Encrypt the symmetric key with the public key
		try:
			print('Encrypting symmetric key...')
			encrypted_key = encrypt_with_public_key(public_key, symmetric_key)
		except:
			print("Error occured while encrypting symmetric key.")
			sys.exit(1)
		# Sign the plaintext message using the private key
		try:
			signature = sign_message(private_key, message_bytes)
		except:
			print("Error occured while creating digital signature.")
			sys.exit(1)
		ciphertext_filename = f"{args.message[0]}.ciphertext"
		encrypted_key_filename = f"{args.message[0]}.aes"
		signature_filename = f"{args.private_key[0]}.signature"
		with open(ciphertext_filename, 'wb') as ciphertext_file:
			ciphertext_file.write(ciphertext)
		with open(encrypted_key_filename, 'wb') as encrypted_key_file:
			encrypted_key_file.write(encrypted_key)
		with open(signature_filename, 'wb') as signature_file:
			signature_file.write(signature)
		print("Done. Here's your ciphertext, encrypted key, and signature:")
		print(f"Resulting ciphertext: {ciphertext_filename}")
		print(f"Encrypted key: {encrypted_key_filename}")
		print(f"Signature file: {signature_filename}")
	elif args.decrypt:
		print('Decrypting message...')
		#=================================================
		# Requires AES decryption to be done by groupmates
		#=================================================
		# try:
		# 	print('Reading ciphertext...')
		# 	with open(args.message[0], 'wb') as file:
		# 		ciphertext = file.read()
		# except:
		# 	print('Error reading ciphertext.')
		# 	sys.exit(1)
		# try:
		# 	print('Reading AES key...')
		# 	with open(args.symmetric_key[0], 'wb') as file:
		# 		symmetric_key_bytes = file.read()
		# except:
		# 	print('Error reading AES key.')
		# 	sys.exit(1)
		# try:
		# 	print('Reading public key...')
		# 	with open(args.public_key[0], 'wb') as file:
		# 		public_key_bytes = file.read()
		# except:
		# 	print('Error reading public key.')
		# 	sys.exit(1)
		# try:
		# 	print('Reading private key...')
		# 	with open(args.private_key[0], 'wb') as file:
		# 		private_key_bytes = file.read()
		# except:
		# 	print('Error reading private key.')
		# 	sys.exit(1)
		# try:
		# 	print('Reading signature...')
		# except:
		# 	sys.exit(1)
		plaintext_filename = f"{args.message[0]}.plaintext"
		print("Done. Here's your plaintext:")
		print(f"Resulting plaintext: {plaintext_filename}")
		pass
	else:
		print("Some strange error occured...")
		sys.exit(1)

if __name__ == "__main__":
	main()
