import sys
from awscrt import checksums

def main():
    if len(sys.argv) != 3:
        print('Checksum type, data file required')
        sys.exit(1)
    checksum_type=sys.argv[1]
    with open(sys.argv[2], 'rb') as f:
      print(checksums.checksum_type(f.read())

if __name__ == "__main__":
    main()