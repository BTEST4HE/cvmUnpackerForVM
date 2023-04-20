import argparse
import pathlib
import unpacker


parser = argparse.ArgumentParser(prog='cvmUnpackerForVM', description='This script converts the ROFSVO4.CVM file in '
                                                                      'Cyber Troopers Virtual-On Marz (SLPM 65303) to '
                                                                      'an ISO file.It has the ability to convert from '
                                                                      'CVM to ISO, but was unable to create a CVM '
                                                                      'that works when the ISO file is modded.It does '
                                                                      'not support conversion of CVM files other than '
                                                                      'Virtual-On Marz.')
mutual = parser.add_mutually_exclusive_group(required=True)
mutual.add_argument('--cvm2iso', dest='cvm_file', type=pathlib.Path, help='converts a CVM file to an ISO file ('
                                                                          'Specify CVM file)')
mutual.add_argument('--iso2cvm', dest='iso_file', type=pathlib.Path, help='converts from ISO file to cvm file ('
                                                                          'Specify iso and CVM Header files)')
parser.add_argument('output', type=pathlib.Path, help='specify output file')
parser.add_argument('cvm_hdr', type=pathlib.Path, nargs='?', default=None, help='specifies CVM Header file path ('
                                                                                'optional with --cvm2iso option)')
args = parser.parse_args()

# Print Arguments
if args.cvm_file:
    print('cvm_file:{}'.format(repr(args.cvm_file)))
elif args.iso_file:
    print('iso_file:{}'.format(repr(args.iso_file)))
if args.output:
    print('output:{}'.format(repr(args.output)))
if args.cvm_hdr:
    print('cvm_hdr:{}'.format(repr(args.cvm_hdr)))


if args.cvm_file:
    if args.cvm_file.is_file():
        unpacker.unpackCvm(args.cvm_file, args.output)
        if args.cvm_hdr:
            unpacker.makeCvmHdr(args.cvm_file, args.cvm_hdr)
    else:
        raise ValueError('CVM file does not exist or is a directory')
elif args.iso_file:
    if args.iso_file.is_file():
        if args.cvm_hdr.is_file():
            unpacker.packCvm(args.iso_file, args.output, args.cvm_hdr)
        else:
            raise ValueError('The CVM Header file does not exist or is a directory.')
    else:
        raise ValueError('The ISO file does not exist or is a directory.')
