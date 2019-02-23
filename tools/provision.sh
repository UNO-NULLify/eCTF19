#!/bin/bash

git pull
python3 provisionSystem.py demo_files/demo_users.txt demo_files/demo_default.txt
python3 provisionGames.py files/generated/FactorySecrets.txt demo_files/demo_games.txt
python3 packageSystem.py files/generated/SystemImage.bif
python3 deploySystem.py /dev/sdb files/uno_BOOT.BIN files/generated/MES.bin files/generated/games
