import sys
from awscrt import checksums

def get_call(checksum_type):
    if checksum_type == "crc32c":
        return checksums.crc32c
    elif checksum_type == "crc64nvme":
        return checksums.crc64nvme
    sys.stderr.write("unrecognized checksum type " + checksum_type)
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        sys.stderr.write('Checksum type, data file path required')
        sys.exit(1)
    with open(sys.argv[2], 'rb') as f:
        function = get_call(sys.argv[1])
        print(function(f.read()))

if __name__ == "__main__":
    main()
