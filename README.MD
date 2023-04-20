# cvmUnpackerForVM
___
This script converts the ROFSVO4.CVM file in Cyber Troopers Virtual-On Marz (SLPM 65303) to an ISO file.
It has the ability to convert from CVM to ISO, but was unable to create a CVM that works when the ISO file is modded.
It does not support conversion of CVM files other than Virtual-On Marz.

# Downloads
___
[Latest release](https://github.com/BTEST4HE/cvmUnpackerForVM/releases/latest)

# Usage
___
##Create iso file from cvm file
`cvmUnpackerForVM --cvm2iso  ROFSVO4.CVM vm_iso.ISO`

##Create iso file and cvm header file from cvm file
`cvmUnpackerForVM --cvm2iso  ROFSVO4.CVM vm_iso.ISO vm_hdr.hdr`

##Create cvm file from iso file and cvm header file (may not create correct cvm file)
`cvmUnpackerForVM --iso2cvm  vm_iso.ISO ROFSVO4.CVM vm_hdr.hdr`

##Options
### Positional arguments
`output`:specify output file  
`cvm_hdr`:specifies CVM Header file path (optional with --cvm2iso option)  

### Optional arguments(options)
`-h, --help`:show this help message and exit  
`--cvm2iso CVM_FILE`:converts a CVM file to an ISO file (Specify CVM file)  
`--iso2cvm ISO_FILE`:converts from ISO file to cvm file (Specify iso and CVM Header files)  
