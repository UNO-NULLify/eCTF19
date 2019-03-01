## **eCTF Design Documentation:** 
The document must describe how your system and game provisioning processes along with your console command protocols protect each of the flags. It also must contain descriptions of how each command works on the system. 

### **Description:**<br/>
The provisioning process has not strayed far from the original diagram given to us in the original documentation. The most significant difference is that before running ProvisionSystem.py a shell script must be run that installs pip and the pycrypto library. The other changes made from the default provisioning process are that we store a nonce and an aes encryption key in mesh_users.h, and we encrypt the games files in ProvisionGames.py. 
-----------------------------------------------------------------------------------------------------------------
### **Flags:**
**1. Rollback (Versioning):**<br/>
Install a “vulnerable” piece of software with a version older than the prepackaged one. To capture this flag, a current version of the software (preinstalled) must be executed prior to running the old version.
_**Protected:**_<br/>
Hash the game on the provisioning side and store the hash into a file that is signed with a public key for the private key of the public key pair and then embed the public key into the header of the game file and then hash it all. Sign the hash with the private key and store a signed hash into a separate file on the SD Card. The game then is encrypted and put into the SD Card.  So now that the game has been loaded from the SD Card to the Board, it will call the decrypt function and decrypt the game each time.

**2. Jailbreak (Arbitrary Code Execution):**<br/>
Use the jailbreak proof program or create a functional equivalent and run it to extract a flag from the PL Memory Region Read/Write Access)
_**Protected:**_<br/>
Read/Write access is mandatory in this memory region for games to operate.
We reviewed the implementation provided by Mitre and made no changes.

**3. Pin Extraction (Confidentiality):**<br/>
Determine the PIN of an account you don’t have access to
_**Protected:**_<br/>
Pins are hashed using SHA256, preventing them from being read, and we implemented a 5 second delay after a failed login attempt to increase the amount of time a brute-force attack would take.

**4. PIN Bypass (Authentication):** 
Run a game from an account you don’t have access to
_**Protected:**_ <br/>
A user must successfully authenticate prior to launching a game, and when they attempt to launch the game, it checks that they can launch the game, and upon success runs the game as the authenticated user. 

**5. Intellectual Property (Confidentiality):**<br/>
Read the value of the flag stored in plaintext in the binary
_**Protected:**_<br/>
We encrypt the binary during provisioning and only decrypt them when they are being played, so running strings are otherwise viewing the file will fail to produce useful output.

**6. Hacker Mods (Integrity):**<br/>
Modify an unwinnable game to gain victory
_**Protected:**_<br/>
Games are encrypted during provisioning and decrypted before use. If the encrypted file is modified, it will fail to successfully decrypt and run.
-----------------------------------------------------------------------------------------------------------------
### **Commands:**
**1. Help:** 
Prints out all the commands available to the user.
_**Output:**_ 
Welcome to the MITRE eCTF entertainment system
The commands available to you are listed below
help
shutdown
logout
list
play
query
install
unistall
	
**2. Shutdown:**
Shutdown the mesh terminal. It does not shutdown the board. It also implements the shutdown function in the mesh shell.

**3. Logout:**
Log out the user from mesh. It brings the user back to the login prompt and it implements the logout function in the mesh shell.

**4. List:**
The name of each game is listed according to the games.txt file when the game is provisioned. It implements the list function from the mesh shell.
_**Output:**_ 
It outputs the game names from games.txt and version of the game.

**5. Play:**
This command takes in filename of the provisioned game as defined by the output requirements for provisionGames.py. The Command writes the game to ram address 0x1fc00040 and the size of the game binary to 0x1fc00000. It then boots the linux kernel from the ram address 0x10000000. The linux kernel will read the game binary and execute it. Usage is play <game>

**6. Query:**
This command will list the installed games of the user. It implements the mesh shell query function.
_**Output:**_
The name of the game is printed out as specified in games.txt when the game is provisioned. 

**7. Install:**
This command takes in filename of the provisioned game as defined by the output requirements for provisionGames.py. It installs the given name for the specified user. It finds the next available spot in the intall table and implements the install function of the mesh shell. Usage is install <name>

**8. Uninstall:**
This command takes in filename of the provisioned games as defined by the output of the provisioned game as defined by the output requirements for provisonGames.py.  It will uninstall the specified game for the given users. This command implements the uninstall function from the mesh shell.

**9. Dump (removed)**  
**10. Reset Flash (removed)**  
