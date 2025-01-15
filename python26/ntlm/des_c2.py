# This file is part of 'NTLM Authorization Proxy Server' http://sourceforge.net/projects/ntlmaps/
# Copyright 2001 Dmitry A. Rozmanov <dima@xenon.spb.ru>
#
# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

from U32 import U32

# --NON ASCII COMMENT ELIDED--
#typedef unsigned char des_cblock[8];
#define HDRSIZE 4

def c2l(c):
    "char[4] to unsigned long"
    l = U32(c[0])
    l = l | (U32(c[1]) << 8)
    l = l | (U32(c[2]) << 16)
    l = l | (U32(c[3]) << 24)
    return l

def c2ln(c,l1,l2,n):
    "char[n] to two unsigned long???"
    c = c + n
    l1, l2 = U32(0), U32(0)

    f = 0
    if n == 8:
        l2 = l2 | (U32(c[7]) << 24)
        f = 1
    if f or (n == 7):
        l2 = l2 | (U32(c[6]) << 16)
        f = 1
    if f or (n == 6):
        l2 = l2 | (U32(c[5]) << 8)
        f = 1
    if f or (n == 5):
        l2 = l2 | U32(c[4])
        f = 1
    if f or (n == 4):
        l1 = l1 | (U32(c[3]) << 24)
        f = 1
    if f or (n == 3):
        l1 = l1 | (U32(c[2]) << 16)
        f = 1
    if f or (n == 2):
        l1 = l1 | (U32(c[1]) << 8)
        f = 1
    if f or (n == 1):
        l1 = l1 | U32(c[0])
    return (l1, l2)

def l2c(l):
    "unsigned long to char[4]"
    c = []
    c.append(int(l & U32(0xFF)))
    c.append(int((l >> 8) & U32(0xFF)))
    c.append(int((l >> 16) & U32(0xFF)))
    c.append(int((l >> 24) & U32(0xFF)))
    return c

def n2l(c, l):
    "network to host long"
    l = U32(c[0] << 24)
    l = l | (U32(c[1]) << 16)
    l = l | (U32(c[2]) << 8)
    l = l | (U32(c[3]))
    return l

def l2n(l, c):
    "host to network long"
    c = []
    c.append(int((l >> 24) & U32(0xFF)))
    c.append(int((l >> 16) & U32(0xFF)))
    c.append(int((l >>  8) & U32(0xFF)))
    c.append(int((l      ) & U32(0xFF)))
    return c

def l2cn(l1, l2, c, n):
    ""
    for i in range(n): c.append(0x00)
    f = 0
    if f or (n == 8):
        c[7] = int((l2 >> 24) & U32(0xFF))
        f = 1
    if f or (n == 7):
        c[6] = int((l2 >> 16) & U32(0xFF))
        f = 1
    if f or (n == 6):
        c[5] = int((l2 >>  8) & U32(0xFF))
        f = 1
    if f or (n == 5):
        c[4] = int((l2      ) & U32(0xFF))
        f = 1
    if f or (n == 4):
        c[3] = int((l1 >> 24) & U32(0xFF))
        f = 1
    if f or (n == 3):
        c[2] = int((l1 >> 16) & U32(0xFF))
        f = 1
    if f or (n == 2):
        c[1] = int((l1 >>  8) & U32(0xFF))
        f = 1
    if f or (n == 1):
        c[0] = int((l1      ) & U32(0xFF))
        f = 1
    return c[:n]

# array of data
# static unsigned long des_SPtrans[8][64]={
# static unsigned long des_skb[8][64]={
from des_data import des_SPtrans, des_skb

def D_ENCRYPT(tup, u, t, s):
    L, R, S = tup
    #print 'LRS1', L, R, S, u, t, '-->',
    u = (R ^ s[S])
    t = R ^ s[S + 1]
    t = ((t >> 4) + (t << 28))
    L = L ^ (des_SPtrans[1][int((t    ) & U32(0x3f))] | \
        des_SPtrans[3][int((t >>  8) & U32(0x3f))] | \
        des_SPtrans[5][int((t >> 16) & U32(0x3f))] | \
        des_SPtrans[7][int((t >> 24) & U32(0x3f))] | \
        des_SPtrans[0][int((u      ) & U32(0x3f))] | \
        des_SPtrans[2][int((u >>  8) & U32(0x3f))] | \
        des_SPtrans[4][int((u >> 16) & U32(0x3f))] | \
        des_SPtrans[6][int((u >> 24) & U32(0x3f))])
    #print 'LRS:', L, R, S, u, t
    return ((L, R, S), u, t, s)


def PERM_OP (tup, n, m):
    "tup - (a, b, t)"
    a, b, t = tup
    t = ((a >> n) ^ b) & m
    b = b ^ t
    a = a ^ (t << n)
    return (a, b, t)

def HPERM_OP (tup, n, m):
    "tup - (a, t)"
    a, t = tup
    t = ((a << (16 - n)) ^ a) & m
    a = a ^ t ^ (t >> (16 - n))
    return (a, t)

shifts2 = [0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0]
