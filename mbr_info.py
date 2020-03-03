import sys
import hashlib
import argparse
import struct
import binascii

partition_type = {
    '0': 'Empty',
    '1': 'FAT12',
    '2': 'XENIX root',
    '3': 'XENIX usr',
    '4': 'FAT16',
    '5': 'Extended',
    '6': 'FAT16B',
    '7': 'IFS/HPFS/NTFS/exFat',
    '8': 'AIX Boot/Logical FAT12 or FAT16',
    '9': 'AIX Data',
    'a': 'OS/2 Boot Manager',
    'b':'FAT32',
    'c': 'FAT32',
    'd': 'Unused',
    'e': 'Fat16',
    'f': 'Extended',
    '10': 'OPUS',
    '11':'Hidden FAT12',
    '12': 'Hibernation',
    '13': 'Unused',
    '14':'FAT16 Hidden',
    '15': 'Extended Hidden',
    '16':'FAT16 Hidden',
    '17': 'Hidden IFS/ HPFS',
    '18': 'AST SmartSleep',
    '19': 'Willowtech Photon',
    '1a': 'Unused',
    '1b': 'FAT32 Hidden',
    '1c': 'FAT32 Hidden/ASUS recovery',
    '1d':'Unused',
    '1e': 'FAT16 Hidden',
    '1f': 'Extended Hidden',
    '20': 'Windows Modile Updata/Overture File System',
    '21': 'FSo2',
    '22': 'Oxygen Extended',
    '23': 'Windows Boot Mobile',
    '24': 'Logical FAT12/FAT16',
    '25': 'Windows Mobile',
    '26': 'Reserved',
    '27': 'Windows Recovery/Hidden NTFS/Rescue Partition/MirOS/RoterBOOT',
    '28': 'Unused',
    '29': 'Unused',
    '2a': 'AtheOS/Reserved',
    '2b': 'Syllable Secure',
    '2c': 'Unused',
    '2d': 'Unused',
    '2e': 'Unused',
    '2f': 'Unused',
    '30': 'Unused',
    '31': 'Reserved',
    '32': 'NOS',
    '33': 'Reserved',
    '34': 'Reserved',
    '35': 'JFS OS2',
    '36': 'Reserved',
    '37': 'Unused',
    '38': 'THEOS v3.2 2gb',
    '39': 'THEOS v4 Spanned',
    '3a': 'THEOS v4 4gb',
    '3b': 'THEOS v4 Extended',
    '3c': 'PartitionMagic Recovery',
    '3d': 'Hidden NetWare',
    '3e': 'Unused',
    '3f': 'Unused',
    '40': 'Venix 80286/PICK R83',
    '41': 'Linux/MINIX (Sharing Disk with DR-DOS)',
    '42': 'Win LVM / Secure FS',
    '43': '"Linux Native (Sharing Disk with DR-DOS)',
    '44': 'GoBack',
    '45': 'Boot-US Boot Manager',
    '46': 'EUMEL/ELAN',
    '47': 'EUMEL/ELAN',
    '48': 'EUMEL/ELAN',
    '49': 'Unused',
    '4a': "Mark Aitchison's ALFS/THIN Lightweight",
    '4b': 'Unused',
    '4c': 'Oberon',
    '4d': 'QNX 4.x',
    '4e': 'QNX 4.x',
    '4f': 'QNX 4.x',
    '50': 'OnTrack Disk Manager',
    '51': 'OnTrack Disk Manager',
    '52': 'Microport SysV/AT',
    '53': 'OnTrack Disk Manger',
    '54': 'OnTrack Disk Manager',
    '55': 'EZ-Drive',
    '56': 'AT&T MS-DOS 3.x Logically Sectored FAT',
    '57': 'DrivePro',
    '58': 'Unused',
    '59': 'Unused',
    '5a': 'Unused',
    '5b': 'Unused',
    '5c': 'Priam EDisk',
    '5d': 'Unused',
    '5e': 'Unused',
    '5f': 'Unused',
    '60': 'Unused',
    '61': 'SpeedStor',
    '62': 'Unused',
    '63': 'UNIX System V',
    '64': 'Novell Netware',
    '65': 'Novell Netware',
    '66': 'Novell Netware',
    '67': 'Novell Netware',
    '68': 'Novell Netware',
    '69': 'Novell Netware',
    '6a': 'Unused',
    '6b': 'Unused',
    '6c': 'BSD Slice',
    '6d': 'Unused',
    '6e': 'Unused',
    '6f': 'Unused',
    '70': 'DiskSecure Mult-Boot',
    '71': 'Reserved',
    '72': 'APTI alternative FAT12',
    '73': 'Reserved',
    '74': 'Scramdisk',
    '75': 'IBM PC/IX',
    '76': 'Reserved',
    '77': 'VNDI',
    '78': 'XOSL FS',
    '79': 'APTI alternative FAT16',
    '7a': 'APTI alternative FAT16',
    '7b': 'APTI alternative FAT16',
    '7c': 'APTI alternative FAT16',
    '7d': 'APTI alternative FAT16',
    '7e': 'Unused',
    '7f': 'Unused',
    '80': 'MINIX <=v1.4a',
    '81': 'MINIX <=v1.4b',
    '82': 'Linux Swap Space/Solaris',
    '83': 'Linux',
    '84': 'Hibernation/Early Linux',
    '85': 'Linux Extended',
    '86': 'NTFS Volume Set',
    '87': 'NTFS Volume Set',
    '88': 'Linux Plaintext Table',
    '89': 'Unused',
    '8a': 'Linux Kernel',
    '8b': 'Legacy Fault Tolerant FAT32',
    '8c': 'Legacy Fault Tolerant FAT32 using BIOS extd INT 13h',
    '8d': 'Free FDISK Hidden Primary DOS FAT12',
    '8e': 'Linux Logical Volume Manager',
    '8f': 'Unused',
    '90': 'Free FDISK Hidden Primary DOS FAT16',
    '91': 'Free FDISK Hidden DOS Extended',
    '92': 'Free FDISK Hidden Primary DOS Large FAT16',
    '93': 'Linux Hidden',
    '94': 'Amoeba Bad Block Table',
    '95': 'MIT EXOPC',
    '96': 'Unused',
    '97': 'Free FDISK Hidden Primary DOS FAT32',
    '98': 'Free FDISK Hidden Primary DOS FAT32 LBA',
    '99': 'DCE376 Logical Drive',
    '9a': 'Free FDISK Hidden Primary DOS FAT16 LBA',
    '9b': 'Free FDISK Hidden Primary DOS FAT16',
    '9c': 'Unused',
    '9d': 'Unused',
    '9e': 'Unused',
    '9f': 'BSD/OS',
    'a0': 'Hibernation',
    'a1': 'Hibernation',
    'a2': 'HPM ARM preloader',
    'a3': 'HP Volume Expansion (SpeedStor Variant)',
    'a4': 'HP Volume Expansion (SpeedStor Variant)',
    'a5': 'BSD/386',
    'a6': 'OpenBSD',
    'a7': 'NeXTSTEP',
    'a8': 'Mac OS X/386BSD/NetBSD/FreeBSD',
    'a9': 'NetBSD',
    'aa': 'Olivetti Fat 12 1.44MB Service',
    'ab': 'Mac OS X Boot Partition',
    'ac': 'Unused',
    'ad': 'ADFS/FileCore',
    'ae': 'ShagOS Filesystem',
    'af': 'Mac OS X HFS',
    'b0': 'BootStar Dummy',
    'b1': 'QNX Neutrino',
    'b2': 'QNX Neutrino',
    'b3': 'HP Volume Expansion (SpeedStor Variant)',
    'b4': 'HP Volume Expansion (SpeedStor Variant)',
    'b5': 'Unused',
    'b6': 'Corrupted Windows NT Mirror Set Master FAT16',
    'b7': 'BSDI',
    'b8': 'BSDI Swap',
    'b9': 'Unused',
    'ba': 'Unused',
    'bb': 'Boot Wizard Hidden',
    'bc': 'Corrupted fault-tolerant FAT32',
    'bd': 'BonnyDOS/286',
    'be': 'Solaris 8 boot',
    'bf': 'Solaris x86',
    'c0': 'Secured FAT partition ',
    'c1': 'Secured FAT12',
    'c2': 'Hidden Linux native ',
    'c3': 'Hidden Linux swap',
    'c4': 'Secured FAT16 ',
    'c5': 'DR-DOS Secured Extended',
    'c6': 'Corrupted Windows NT Volume / Stripe Set',
    'c7': 'Corrupted Windows NT Volume / Stripe Set',
    'c8': '"Reserved for DR-DOS 8.0+',
    'c9': 'Reserved for DR-DOS 8.0+',
    'ca': 'Reserved for DR-DOS 8.0+',
    'cb': 'DR-DOS 7.04+ Secured FAT32 CHS',
    'cc': 'DR-DOS 7.04+ Secured FAT32 CHS',
    'cd': 'CTOS Memdump',
    'ce': 'DR-DOS 7.04+ FAT16X LBA',
    'cf': 'DR-DOS 7.04+ Secured EXT DOS LBA',
    'd0': 'Multiuser DOS Secured',
    'd1': 'Old Multiuser DOS Secured FAT12',
    'd2': 'Unused',
    'd3': 'Unused',
    'd4': 'Old Multiuser DOS Secured FAT16 <32M',
    'd5': 'Old Multiuser DOS Secured extended',
    'd6': 'Old Multiuser DOS Secured FAT16 >=32M',
    'd7': 'Unused',
    'd8': 'CP/M-86',
    'd9': 'Unused',
    'da': 'Non-FS Data',
    'db': 'Digital Research CP/M',
    'dc': 'Unused',
    'dd': 'Hidden CTOS Memdump',
    'de': 'Dell Utilities FAT',
    'df': 'DG/UX virtual disk/EMBRM',
    'e0': 'ST AVFS',
    'e1': 'FAT12',
    'e2': 'Unused',
    'e3': 'Read-only FAT12 ',
    'e4': 'SpeedStor 16-bit FAT Extended <1024 cyl.',
    'e5': 'Tandy MS-DOS with Logically Sectored FAT',
    'e6': 'Storage Dimensions SpeedStor',
    'e7': 'Unused',
    'e8': 'Linux Unified Key ',
    'e9': 'Unused',
    'ea': 'Unused',
    'eb': 'BeOS BFS',
    'ec': 'SkyFS',
    'ed': 'EDC loader',
    'ee': 'GPT protective MBR[',
    'ef': 'EFI File System',
    'f0': 'Linux/PA-RISC Boot Loader',
    'f1': 'Storage Dimensions SpeedStor',
    'f2': 'DOS 3.3+ Secondary',
    'f3': 'Reserved',
    'f4': 'SpeedStor Large',
    'f5': 'Prologue Multi-Volume',
    'f6': 'Storage Dimensions SpeedStor',
    'f7': 'EFAT/Solid State',
    'f8': 'Unused',
    'f9': 'pCache',
    'fa': 'Bochs',
    'fb': 'VMWare File System',
    'fc': 'VMWare Swap',
    'fd': 'Linux RAID',
    'fe': 'Windows NT Disk Administrator Hidden',
    'ff': 'Xenix BAD Block Table'
}

LBA = []
Last_8 = []

#Define Parse MBR
def parse_MBR(arg):
    return arg[446:]

#Define Convert
def convert(arg):

    combine = b''

    for i in range(4):
        char = struct.pack("<B", arg[i])    
        combine += char

    data = struct.unpack("<L", combine)[0]
    return data

#Define Print MBR
def print_MBR(part):
    part_type = hex(part[4])[2:]
    print('({}) {}, {}, {}'.format(part_type.zfill(2), partition_type[part_type], str(convert(part[8:12])).zfill(10), str(convert(part[12:16])).zfill(10)))
    LBA.append(convert(part[8:12]))

#Define Partioning
def partitioning(MBR):
    for i in range(4):
        part = struct.unpack("<BBBBBBBBBBBBBBBB", MBR[(16*i):(16*(i+1))])
        if(sum(part)):
            print_MBR(part)

#Define Get Last 8 Bytes and print
def get_Last_8(arg):
    for i in arg:
        i = (i*512)+504
        Last_8.append(i)
    
    for i,j in enumerate(Last_8):
        print("Partition number: ",i+1,"\nLast 8 bytes of boot record: ", " ".join("{:02x}".format(content[j+k]) for k in range(8)))

#Declare an arguement
parser = argparse.ArgumentParser()
parser.add_argument("file") 
args = parser.parse_args()

file_path = args.file

#Write SHA1(Raw File) to a file
file_sha1 = hashlib.sha1(open(file_path,'rb').read()).hexdigest()
fp_name_sha1 = "SHA1-"+ file_path.split('/')[-1] + ".txt"
fp = open(fp_name_sha1,"w") 
fp.write(file_sha1)
fp.close()

#Write MD5(Raw File) to a file
file_md5 = hashlib.md5(open(file_path,'rb').read()).hexdigest()
fp_name_md5 = "MD5-"+ file_path.split('/')[-1] + ".txt"
fp = open(fp_name_md5,"w") 
fp.write(file_md5)
fp.close()

#Read Raw Image
with open(file_path, 'rb') as content_file:
    content = content_file.read()
with open(file_path, 'rb') as content_file:
    trial = content_file.read(512)

#Call Parse MBR
MBR = parse_MBR(trial)

#Call Partition
partitioning(MBR)

#Call Get Last 8
get_Last_8(LBA)


