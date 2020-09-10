import sys
import pefile
import datetime
import hashlib
import os
import ssdeep
import magic
import json


# Get summary PE info
def get_info(pe, filename):
    ftype = magic.from_file(filename)
    fname = os.path.basename(filename)
    fsize = os.path.getsize(filename)
    dll = pe.FILE_HEADER.IMAGE_FILE_DLL
    nsec = pe.FILE_HEADER.NumberOfSections
    tstamp = pe.FILE_HEADER.TimeDateStamp
    try:
        """ return date """
        tsdate = datetime.datetime.fromtimestamp(tstamp)
    except:
        """ return timestamp """
        tsdate = str(tstamp) + " [Invalid date]"
    return ftype, fname, fsize, tsdate, dll, nsec


# Get hashes from input PE
def get_hash(pe, filename):
    # Import Hash
    ih = pe.get_imphash()
    fh = open(filename, 'rb')
    m = hashlib.md5()
    s = hashlib.sha1()
    s2 = hashlib.sha256()
    s5 = hashlib.sha512()

    while True:
        data = fh.read(8192)
        if not data:
            break

        m.update(data)
        s.update(data)
        s2.update(data)
        s5.update(data)

    md5 = m.hexdigest()
    sha1 = s.hexdigest()
    sha2 = s2.hexdigest()
    sha5 = s5.hexdigest()

    hashdeep = ssdeep.hash_from_file(filename)
    return md5, sha1, ih, hashdeep, sha2, sha5


def main(exefile):
    try:
        exe = pefile.PE(exefile)
    except OSError as e:
        print(e)
        sys.exit()
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
        print("[!] The file is not a valid PE")
        sys.exit()

    ftype, fname, fsize, tsdate, dll, nsec = get_info(exe, exefile)
    md5, sha1, ih, hashdeep, sha2, sha5 = get_hash(exe, exefile)

    print("File type:\t %s" % ftype)
    print("File name:\t %s" % fname)
    print("File size:\t %s Bytes" % fsize)
    print("Compile time:\t %s" % tsdate)
    print("Entry point:\t 0x%.8x" % exe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print("Image base:\t 0x%.8x" % exe.OPTIONAL_HEADER.ImageBase)
    print("Hash MD5:\t %s" % md5)
    print("Hash SHA2:\t %s" % sha2)
    print("Import hash:\t %s" % ih)
    print("Ssdeep:\t\t %s" % hashdeep)

    json_report = {'PE Summary':{'File type': ftype, 'File name': fname, 'File size': fsize, 'Compile time': tsdate, 'Entry point':'0x%.8x' % exe.OPTIONAL_HEADER.AddressOfEntryPoint, 'Image base': '0x%.8x' % exe.OPTIONAL_HEADER.ImageBase, 'Hash MD5': md5, 'Hash SHA2': sha2, 'Import Hash': ih, 'Ssdeep': hashdeep}}
    print(json.dumps(json_report, default=str, indent=4))

if __name__ == "__main__":
    try:
        exefile = sys.argv[1]
        main(exefile)
    except IndexError:
        print("[!] You must supply a PE file!")
