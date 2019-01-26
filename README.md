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
2. Modify configuration options contained in `provision/config.rb`, change $petalinux_git value to the URL of **this** repository.
3. Download the Petalinux Tools from https://www.xilinx.com/member/forms/download/xef.html?filename=petalinux-v2017.4-final-installer.run with username and password `tworort:asdfghjk1!` and put it in the `downloads` folder.
  - if you want to make hardware configuration changes download https://www.xilinx.com/member/forms/download/xef-vivado.html?filename=Xilinx_Vivado_SDK_Web_2017.4_1216_1_Lin64.bin using the same login information and move it to the downloads directory.
  - if you want to wirte petalinux applications download https://www.xilinx.com/member/forms/download/xef.html?filename=Xilinx_SDK_2017.4_1216_1_Lin64.bin using the same login information and move it to the downloads directory.
4. Create, boot, and provision the VM via the `vagrant up` command. **Note that the GUI will appear before the vagrant provisioning process has completed.** Wait for the vagrant process to finish before interacting with the VM.
5. Restart the VM for all changes to take place with `vagrant halt && vagrant up`.
6. Login the vm with username and password `vagrant:vagrant` or ssh into VM with `vagrant ssh`

> Note: To start the provisioning process again use `vagrant destroy` and go back to step 4.


### To build the system:

0. Ensure all previous steps have been completed.
1. Go into MES tools directory `cd ~/MES/tools`
2. Build the system: `python3 provisionSystem.py demo_files/demo_users.txt demo_files/demo_default.txt`
3. Build the games: `python3 provisionGames.py files/generated/FactorySecrets.txt demo_files/demo_games.txt`
4. Package the system: `python3 packageSystem.py files/generated/SystemImage.bif`
5. Insert SD card into host computer and passthrough to VM.
6. Identify SD card in VM `lsblk`
7. Deploy system to SD card: `python3 deploySystem.py /dev/sdX files/uno_BOOT.BIN files/generated/MES.bin files/generated/games` (replacing `/dev/sdX` with the appropriate device)
8. Remove SD card and place it in the board
9. Plug in the board to the host computer and on the Arty Z7 board, move jumper JP4 to the two pins labeled 'SD'
10. Access UART `sudo minicom -D /dev/ttyUSB1`. You will need to disable the `hardware flow control` setting to have UART work appropriately. To do so, press `control A` and then `z` while running `minicom`, then hit `O`, go to `Serial port setup`, and then press `F`. You may want to save this configuration so you don't need to set this up every time you run `minicom`.
11. Press the `POBR` button on the board to reset it. You should now see the mesh shell boot and will be greeted with the login prompt
12. Log in with the demo credentials `demo:00000000`
13. List Mesh commands with `help`

> Note: Games will boot to an external display through HDMI-out.
