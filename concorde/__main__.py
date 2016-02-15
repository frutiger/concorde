# concorde.__main__

import sys

import concorde.cli

def main():
    concorde.cli.main(sys.argv, sys.stderr)

if __name__ == '__main__':
    main()

