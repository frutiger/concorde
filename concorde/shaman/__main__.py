# shaman.__main__

import os
import sys

from .profile import Profile

def main():
    if len(sys.argv) > 1:
        os.chdir(sys.argv[1])
    Profile().run()

if __name__ == '__main__':
    main()

