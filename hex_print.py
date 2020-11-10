#!/usr/bin/python

def hex_print(temp):
    for i in range(int(len(temp)/2)):
        print(temp[i*2:(i*2)+2], end=' ')
    print()
