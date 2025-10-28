Taken from PR #1
- Contains a `main.py` file which is intended to accept command line parameters for actually running the program.
  - When user selects `-g`:
    - Generate a public and private key and saves each one to a file.
      - Public key: `filename.pub`
      - Private key: `filename`
    - User can specify a filename using `-n`, otherwise it uses a default filename.
  - When user selects `-e`:
    - Check for message file using `-m`, public key file using `-p`, and private key file using `-r`
    - No actual encryption performed because those functions haven't been implemented yet
  - When user selects `-d`:
    - Check for message file using `-m`, public key file using `-p`, and private key file using `-r`
    - No actual decryption performed because those functions haven't been implemented yet
  - If user doesn't select any command line parameters, or selects `-h`:
    - Print a help message explaining the command line parameters, then exit.
- Copied the cryptographic functions are in a separate file called `crypto_functions.py`, and the command line interface is `main.py`
  - We still have the original `CS351_PROJECT_2.py` file intact, though, in case anyone still needs it.

The file `main.py` takes the following command line arguments:
```# Operations:
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
# If keypair_name is omitted, use a default name```
