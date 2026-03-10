#!/bin/bash

rm -rf .git
rm -rf ftrace
rm -rf include
rm -rf modules
rm -rf scripts
rm -rf ..module-common.o.cmd
rm -rf .main.o.cmd
rm -rf .module-common.o
rm -rf .Module.symvers.cmd
rm -rf .modules.order.cmd
rm -rf .singularity.ko.cmd
rm -rf .singularity.mod.cmd
rm -rf .singularity.mod.o.cmd
rm -rf .singularity.o.cmd
rm -rf load_and_persistence.sh
rm -rf main.c
rm -rf main.o
rm -rf Makefile
rm -rf Module.symvers
rm -rf modules.order
rm -rf README.md
rm -rf singularity.ko
rm -rf singularity.mod
rm -rf singularity.mod.c
rm -rf singularity.mod.o
rm -rf singularity.o
cd ..
sudo find Singularity -type f -exec shred -u {} \; 
rm -rf Singularity

echo "[*] Done! [*]"
