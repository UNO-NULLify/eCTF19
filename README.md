# 2019 Collegiate eCTF Setup

This repository contains UNO's code for the 2019 MITRE eCTF.

This document contains instructions to set up the development environment.

## RequiredTools

To host the VM using Vagrant you must have the following tools installed on your host machine:

- [VirtualBox](https://www.virtualbox.org/) (can be installed from distro repository)
- [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads) (this too)
- [Vagrant](https://www.vagrantup.com/) (install specifically from this site)


Install VirtualBox and the VirtualBox Extension Pack first.

On Linux, you will also need to add your user to the `vboxusers` group.

Next, install the latest version of Vagrant.

## System Requirements

- At least **50GB** of disk space once all the above tools are installed. You will need more if you decide to install Vivado.
- At least **4 CPU** threads. You can operate with less but you will need to change the number of CPUs in `provision/config.rb`
- At least **8 GB** of ram. You can operate with less but you will need to modify the amount of provisioned ram in `provision/config.rb`. We recommend using no more than half of the total amount of RAM on your system.

## Development Environment Instructions

Follow the below instructions to provision the development environment.

Note, this will take a **LONG** time so be patient!

When the petalinux tools are being installed, you may want to get up and do something else while it works.

It could take over an hour depending on your system specs.

### To use the VM:

0. Clone the [Vagrant Setup repository](https://github.com/mitre-cyber-academy/2019-ectf-vagrant) onto your machine.
1. Navigate to the directory where this `README` is located; this should be where the `Vagrantfile` is.
2. Modify configuration options contained in `provision/config.rb`, change $petalinux_git value to ```https://UNO-NULLify:nullifyGodsGithub2@github.com/UNO-NULLify/eCTF19```.
3. Download the [Petalinux Tools](https://www.xilinx.com/member/forms/download/xef.html?filename=petalinux-v2017.4-final-installer.run) with username and password `tworort:asdfghjk1!` and put it in the `downloads` folder. 
4. Create, boot, and provision the VM via the `vagrant up` command. The GUI will appear before the vagrant provisioning process has completed. **Wait for the vagrant process to finish before interacting with the VM.**
5. Restart the VM for all changes to take place with `vagrant halt && vagrant up`.
6. Login the vm with username and password `vagrant:vagrant` or ssh into VM with `vagrant ssh`

> Note: To start the provisioning process again use `vagrant destroy` and go back to step 4.


### To build the system:

0. Ensure all previous steps have been completed.
1. Go into MES tools directory `cd ~/MES/tools`<br>
2. Build the system: `python3 provisionSystem.py demo_files/demo_users.txt demo_files/demo_default.txt`
3. Build the games: `python3 provisionGames.py files/generated/FactorySecrets.txt demo_files/demo_games.txt`
4. Package the system: `python3 packageSystem.py files/generated/SystemImage.bif`
5. Insert SD card into host computer and passthrough to VM.
6. Identify SD card in VM `lsblk`
7. Deploy system to SD card: `python3 deploySystem.py /dev/sdX files/uno_BOOT.BIN files/generated/MES.bin files/generated/games` (replacing `/dev/sdX` with the appropriate device)
8. Remove SD card and place it in the board
9. Plug in the board to the host computer and on the Arty Z7 board, move jumper JP4 to the two pins labeled 'SD'
10. Access UART `sudo minicom -D /dev/ttyUSB1`. You will need to disable the `hardware flow control` setting to have UART work appropriately. To do so, press `control A` and then `z` while running `minicom`, then hit `O`, go to `Serial port setup`, and then press `F`. You may want to save this configuration so you don't need to set this up every time you run `minicom`.
11. Press the `PORB` button on the board to reset it. You should now see the mesh shell boot and will be greeted with the login prompt
12. Log in with the demo credentials `demo:00000000`
13. List Mesh commands with `help`

> Note: Games will boot to an external display through HDMI-out.

## **eCTF Design Documentation:** 
The document must describe how your system and game provisioning processes along with your console command protocols protect each of the flags. It also must contain descriptions of how each command works on the system. 

### **Description:**
The provisioning process has not strayed far from the original diagram given to us in the original documentation. The most significant difference is that before running ProvisionSystem.py a shell script must be run that installs pip and the pycrypto library. The other changes made from the default provisioning process are that we store a nonce and an aes encryption key in mesh_users.h, and we encrypt the games files in ProvisionGames.py. 
-----------------------------------------------------------------------------------------------------------------
### **Flags:**
**1. Rollback (Versioning):**
Install a “vulnerable” piece of software with a version older than the prepackaged one. To capture this flag, a current version of the software (preinstalled) must be executed prior to running the old version.
_**Protected:**_ 
Hash the game on the provisioning side and store the hash into a file that is signed with a public key for the private key of the public key pair and then embed the public key into the header of the game file and then hash it all. Sign the hash with the private key and store a signed hash into a separate file on the SD Card. The game then is encrypted and put into the SD Card.  So now that the game has been loaded from the SD Card to the Board, it will call the decrypt function and decrypt the game each time.

**2. Jailbreak (Arbitrary Code Execution):** 
Use the jailbreak proof program or create a functional equivalent and run it to extract a flag from the PL Memory Region Read/Write Access)
_**Protected:**_ 
Read/Write access is mandatory in this memory region for games to operate.
We reviewed the implementation provided by Mitre and made no changes.

**3. Pin Extraction (Confidentiality):**
Determine the PIN of an account you don’t have access to
_**Protected:**_ 
Pins are hashed using SHA256, preventing them from being read, and we implemented a 5 second delay after a failed login attempt to increase the amount of time a brute-force attack would take.

**4. PIN Bypass (Authentication):** 
Run a game from an account you don’t have access to
_**Protected:**_ 
A user must successfully authenticate prior to launching a game, and when they attempt to launch the game, it checks that they can launch the game, and upon success runs the game as the authenticated user. 

**5. Intellectual Property (Confidentiality):**
Read the value of the flag stored in plaintext in the binary
_**Protected:**_ 
We encrypt the binary during provisioning and only decrypt them when they are being played, so running strings are otherwise viewing the file will fail to produce useful output.

**6. Hacker Mods (Integrity):** 
Modify an unwinnable game to gain victory
_**Protected:**_
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