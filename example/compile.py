#!/usr/bin/env python

import os
import sys

def main():
    if len(sys.argv) < 3:
        print('Usage: python {} source out'.format(sys.argv[0]))
        return
    os.system('gcc -o {} {} -shared -fPIC'.format(sys.argv[2], sys.argv[1]))


if __name__ == '__main__':
    main()
