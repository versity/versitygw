import sys
from awscrt import checksums

def main():
    if len(sys.argv) != 2:
        print('Data file path, checksum type required')
        sys.exit(1)
    checksum_type=sys.argv[2]
    with open(sys.argv[1], 'rb') as f:
      print(checksums.checksum_type(f.read())

if __name__ == "__main__":
    main()