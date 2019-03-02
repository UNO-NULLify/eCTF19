## **eCTF Design Documentation:** 
The document must describe how your system and game provisioning processes along with your console command protocols protect each of the flags. It also must contain descriptions of how each command works on the system. 

### **Commands:**
**1. Help:** 
Prints out all the commands available to the user.<br/>
_**Output:**_
It outputs all commands available:   
help,
shutdown,
logout,
list,
play,
query,
install,
and unistall,
	
**2. Shutdown:**
Shutdown the mesh terminal. It does not shutdown the board. It also implements the shutdown function in the mesh shell.

**3. Logout:**
Log out the user from mesh. It brings the user back to the login prompt and it implements the logout function in the mesh shell.

**4. List:**
The name of each game is listed according to the games.txt file when the game is provisioned. It implements the list function from the mesh shell.<br/>
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

**9. Dump (removed)**<br/>
**10. Reset Flash (removed)**
