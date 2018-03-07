# ELF binary infection for x86_64 executable files

## Synopsis
Pestilence is a self-replicating oligomorphic virus.
It recusively replicates in /tmp/test(2) directories adding a custom "signature" string into each infected file.
To check the signature, simply copy/paste the following command :
`strings /tmp/test* | grep <signatureName>`

## Mandatory
- [ ] Infect all of the binaries located in /tmp/test and /tmp/test2 directories
- [ ] Infect all of the binaries of type executable ELF x86_64
- [ ] Insert a signature like 'Pestilence version 1.0 (c)oded by first-login - second-login'
- [ ] Create an obfuscation method to hide the infection routine
- [ ] Create a deobfuscation method that will run the infection
- [ ] DO NOT re-infect the an already infected file
- [ ] DO NOT run infection if a specific process is running on host
- [ ] DO NOT run infection if the program is launched into gdb, etc

## Bonus
- [ ] Infect all files from the root directory
- [ ] Pack the binary with a compression algorithm
- [ ] Add a secret backdoor (open port, ...)
