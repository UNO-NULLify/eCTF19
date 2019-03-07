#!/usr/bin/env python3

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os
import argparse
import re
import subprocess

# Path to the generated games folder
gen_path = "files/generated/games"

block_size = 65536


def gen_cipher(content):
    scontent = [x.strip() for x in content]
    nonce = scontent[0].encode()
    key = scontent[1].encode()
    keypairP = scontent[2].encode()
    keypairQ = scontent[3].encode()
    keypairFR = scontent[4].encode()
    keypairSR = scontent[5].encode()
    keypairCRT = scontent[6].encode()
    return (key, nonce, keypairP, keypairQ, keypairFR, keypairSR, keypairCRT)

def provision_game(line, cipher):
    """Given a line from games.txt, provision a game and write to the
    appropriate directory

    line: string from games.txt to create a game for
    """
    # Regular expression to parse out the necessary parts of the line in the
    # games.txt file. The regular expression works as follows:
    # 1. Match a file name and capture it
    # 2. Skip over any whitespace
    # 3. Match the game name and capture it
    # 4. Skip over whitespace
    # 5. Match the group (major.minor)

    reg = r'^\s*([\w\/\-.\_]+)\s+([\w\-.\_]+)\s+(\d+\.\d+|\d+)((?:\s+\w+)+)'
    m = re.match(reg, line)
    if not m:
        return

    # Path to the game
    g_path = m.group(1)
    # Name of the game
    name = m.group(2)
    # Game version
    version = m.group(3)
    # List of users (strings) that are allowed to play this game
    users = m.group(4).split()

    # Open the path to the games in binary mode
    try:
        f = open(g_path, "rb")
    except Exception as e:
        print("Error, could not open game: %s" % (e))
        exit(1)

    # The output of the game into the file should be:
    # gamename-vmajor.minor
    f_out_name = name + "-v" + version
    # Open the output file in binary mode
    try:
        f_out = open(os.path.join(gen_path, f_out_name), "wb")
    except Exception as e:
        print("Error, could not open game output file: %s" % (e))
        f.close()
        exit(1)

    # Write the game header to the top of the file
    # The game header takes the form of the version, name, and user information
    # one separate lines, prefaced with the information for what the data is
    # (version, name, users), separated by a colon. User information is space
    # separated
    # For example:
    # version:1.0
    # name:2048
    # users:drew ben lou hunter
    #f_out = f_out.name
    f_out.write(bytes("version:%s\n" % (version), "utf-8"))
    f_out.write(bytes("name:%s\n" % (name), "utf-8"))
    f_out.write(bytes("users:%s\n" % (" ".join(users)), "utf-8"))

    # Read in the binary source
    # block_size used as
    # we can't be sure of the size of each game
    # best be careful by reading a certain number of bytes each time
    g_src = f.read(block_size)
    while g_src:
        f_out.write(g_src)
        g_src = f.read(block_size)

    # Close the files
    f_out.close()
    f.close()

    # Write the binary source
    f_hash_out = f_out_name + ".SHA256"
    f_hash_sig_out = f_hash_out + ".SIG"
    try:
        print(cipher[2])
        key = RSA.import_key(cipher[2])
        print(key.exportKey())
        h = SHA256.new()

        # hash game and save to file, tested locally
        with open(f_out.name, 'rb') as to_hash:
            buf = to_hash.read(block_size)
            while len(buf) > 0:
                h.update(buf)
                buf = to_hash.read(block_size)

        print("wrote contents to binary: " + f_out.name)
        # to_hash/f_out closed implicitly outside of with

        with open(os.path.join(gen_path, f_hash_out), "w+") as hash:
            hash.write(h.hexdigest())

        print("wrote hash to file: " + str(os.path.join(gen_path, f_hash_out)))

        # need to verify here cuz why not
        try:
            subprocess.check_call("gcc -o cmdSIG cmdLineSIG.c", shell=True)
        except Exception as e:
            print("NOPE2: ", e)
        try:
            print("Gen_path: ", gen_path)
            print("Key: ", cipher[0])
            print("Nonce: ", cipher[1])
            print("File Name: ", f_out_name)
            subprocess.check_call("./cmdSIG %s %s %s %s %s %s %s" % (gen_path+"/"+f_hash_sig_out, h.hexdigest(),
                                                     cipher[2].decode(), cipher[3].decode(), cipher[4].decode(), cipher[5].decode(), cipher[6].decode()), shell=True)
        except Exception as e:
            print("NOPENOPE2: ", e)


        # this is all in 1 try/catch block because we cannot have one
        # part (writing header, hashing, signing, etc) to fail whilst the others continue

    except Exception as e:
        print("Error, could write OR hash binary OR write signature to source: %s" % (e))
        # f_out.close()
        # exit(1)

    # encrypt games
    # 1. GCC the cmdLineAES.c with
    try:
        subprocess.check_call("gcc -o cmdAES cmdLineAES.c", shell=True)
    except Exception as e:
        print("NOPE: ", e)
    # 2. Create Subprocess with arguments
    try:
        print("Gen_path: ", gen_path)
        print("Key: ", cipher[0])
        print("Nonce: ", cipher[1])
        print("File Name: ", f_out_name)
        subprocess.check_call("./cmdAES %s %s %s" % (gen_path+"/"+f_out_name,
                                                     cipher[0].decode('utf-8'), cipher[1].decode('utf-8')), shell=True)

    except Exception as e:
        print("NOPENOPE: ", e)

    print("    %s -> %s" % (g_path, os.path.join(gen_path, f_out_name)))


def main():
    # argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('factory_secrets',
                        help=("This file is the FactorySecrets.txt file "
                              "generated by provisionSystem.py"))
    parser.add_argument('games',
                        help=("A text file containing game information in a "
                              "MITRE defined format."))
    args = parser.parse_args()

    # open factory secrets
    try:
        with open(args.factory_secrets) as f:
            content = f.readlines()
    except Exception as e:
        print("Couldn't open file %s" % (args.factory_secrets))
        exit(2)

    # Open the games file
    try:
        f_games = open(args.games, "r")
    except Exception as e:
        print("Couldn't open file %s" % (args.games))
        exit(2)

    cipher = gen_cipher(content)

    subprocess.check_call("mkdir -p %s" % (gen_path), shell=True)

    print("Provision Games...")

    # Provision each line in the games file
    for line in f_games:
        provision_game(line, cipher)

    print("Done Provision Games")

    exit(0)


if __name__ == '__main__':
    main()
