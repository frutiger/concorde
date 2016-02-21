# concorde.cli.__main__

import sys

from . import cli

def main():
    cli.main(sys.argv, sys.stderr)

if __name__ == '__main__':
    main()

