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

import struct
import base64
import string
import des
import hashlib
import hmac
import random
import re
import binascii
from socket import gethostname

from ntlm_2 import *

def create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, domain, password, NegotiateFlags):
    ""
    is_unicode  = NegotiateFlags & NTLM_NegotiateUnicode
    is_NegotiateExtendedSecurity = NegotiateFlags & NTLM_NegotiateExtendedSecurity
    
    flags =  struct.pack('<I',NTLM_TYPE2_FLAGS)

    BODY_LENGTH = 72
    Payload_start = BODY_LENGTH # in bytes

    Workstation = gethostname().upper()
    DomainName = domain.upper()
    UserName = user
    EncryptedRandomSessionKey = ""
    if is_unicode:
        Workstation = Workstation.encode('utf-16-le')
        DomainName = DomainName.encode('utf-16-le')
        UserName = UserName.encode('utf-16-le')
        EncryptedRandomSessionKey = EncryptedRandomSessionKey.encode('utf-16-le')
    LmChallengeResponse = calc_resp(create_LM_hashed_password_v1(password), nonce)
    NtChallengeResponse = calc_resp(create_NT_hashed_password_v1(password), nonce)
    
    if is_NegotiateExtendedSecurity:
        pwhash = create_NT_hashed_password_v1(password, UserName, DomainName)
        ClientChallenge = ""
        for i in range(8):
           ClientChallenge+= chr(random.getrandbits(8))
        (NtChallengeResponse, LmChallengeResponse) = ntlm2sr_calc_resp(pwhash, nonce, ClientChallenge) #='\x39 e3 f4 cd 59 c5 d8 60')
    Signature = 'NTLMSSP\0'           
    MessageType = struct.pack('<I',3)  #type 3
    
    DomainNameLen = struct.pack('<H', len(DomainName))
    DomainNameMaxLen = struct.pack('<H', len(DomainName))
    DomainNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(DomainName)
    
    UserNameLen = struct.pack('<H', len(UserName))
    UserNameMaxLen = struct.pack('<H', len(UserName))
    UserNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(UserName)
    
    WorkstationLen = struct.pack('<H', len(Workstation))
    WorkstationMaxLen = struct.pack('<H', len(Workstation))
    WorkstationOffset = struct.pack('<I', Payload_start)
    Payload_start += len(Workstation)
    
    
    LmChallengeResponseLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseMaxLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(LmChallengeResponse)
    
    NtChallengeResponseLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseMaxLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(NtChallengeResponse)
    
    EncryptedRandomSessionKeyLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyMaxLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyOffset = struct.pack('<I',Payload_start)
    Payload_start +=  len(EncryptedRandomSessionKey)
    NegotiateFlags = flags
    
    ProductMajorVersion = struct.pack('<B', 5)
    ProductMinorVersion = struct.pack('<B', 1)
    ProductBuild = struct.pack('<H', 2600)
    VersionReserved1 = struct.pack('<B', 0)
    VersionReserved2 = struct.pack('<B', 0)
    VersionReserved3 = struct.pack('<B', 0)
    NTLMRevisionCurrent = struct.pack('<B', 15)
    
    MIC = struct.pack('<IIII',0,0,0,0)
    msg3 = Signature + MessageType + \
            LmChallengeResponseLen + LmChallengeResponseMaxLen + LmChallengeResponseOffset + \
            NtChallengeResponseLen + NtChallengeResponseMaxLen + NtChallengeResponseOffset + \
            DomainNameLen + DomainNameMaxLen + DomainNameOffset + \
            UserNameLen + UserNameMaxLen + UserNameOffset + \
            WorkstationLen + WorkstationMaxLen + WorkstationOffset + \
            EncryptedRandomSessionKeyLen + EncryptedRandomSessionKeyMaxLen + EncryptedRandomSessionKeyOffset + \
            NegotiateFlags + \
            ProductMajorVersion + ProductMinorVersion + ProductBuild + \
            VersionReserved1 + VersionReserved2 + VersionReserved3 + NTLMRevisionCurrent
    assert BODY_LENGTH==len(msg3), "BODY_LENGTH: %d != msg3: %d" % (BODY_LENGTH,len(msg3))
    Payload = DomainName + UserName + Workstation + LmChallengeResponse + NtChallengeResponse + EncryptedRandomSessionKey
    msg3 += Payload
    msg3 = base64.encodestring(msg3)
    msg3 = string.replace(msg3, '\n', '')
    return msg3
            
def calc_resp(password_hash, server_challenge):
    """calc_resp generates the LM response given a 16-byte password hash and the
        challenge from the Type-2 message.
        @param password_hash
            16-byte password hash
        @param server_challenge
            8-byte challenge from Type-2 message
        returns
            24-byte buffer to contain the LM response upon return
    """
    # padding with zeros to make the hash 21 bytes long
    password_hash = password_hash + '\0' * (21 - len(password_hash))
    res = ''
    dobj = des.DES(password_hash[0:7])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = des.DES(password_hash[7:14])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = des.DES(password_hash[14:21])
    res = res + dobj.encrypt(server_challenge[0:8])
    return res
    
def ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge='\xaa'*8, Time='\0'*8):
    LmChallengeResponse = hmac.new(ResponseKeyLM, ServerChallenge+ClientChallenge).digest() + ClientChallenge
    
    Responserversion = '\x01'
    HiResponserversion = '\x01'
    temp = Responserversion + HiResponserversion + '\0'*6 + Time + ClientChallenge + '\0'*4 + ServerChallenge + '\0'*4 
    NTProofStr  = hmac.new(ResponseKeyNT, ServerChallenge + temp).digest()
    NtChallengeResponse = NTProofStr + temp
    
    SessionBaseKey = hmac.new(ResponseKeyNT, NTProofStr).digest()
    return (NtChallengeResponse, LmChallengeResponse)

def ntlm2sr_calc_resp(ResponseKeyNT, ServerChallenge, ClientChallenge='\xaa'*8):
    import hashlib
    LmChallengeResponse = ClientChallenge + '\0'*16
    sess = hashlib.md5(ServerChallenge+ClientChallenge).digest()
    NtChallengeResponse = calc_resp(ResponseKeyNT, sess[0:8])
    return (NtChallengeResponse, LmChallengeResponse)

def create_LM_hashed_password_v1(passwd):
    "setup LanManager password"
    "create LanManager hashed password"
    # if the passwd provided is already a hash, we just return the first half
    if re.match(r'^[\w]{32}:[\w]{32}$',passwd):
        return binascii.unhexlify(passwd.split(':')[0])

    # fix the password length to 14 bytes
    passwd = string.upper(passwd)
    lm_pw = passwd + '\0' * (14 - len(passwd))
    lm_pw = passwd[0:14]

    # do hash
    magic_str = "KGS!@#$%" # page 57 in [MS-NLMP]

    res = ''
    dobj = des.DES(lm_pw[0:7])
    res = res + dobj.encrypt(magic_str)

    dobj = des.DES(lm_pw[7:14])
    res = res + dobj.encrypt(magic_str)

    return res
    
def create_NT_hashed_password_v1(passwd, user=None, domain=None):
    "create NT hashed password"
    # if the passwd provided is already a hash, we just return the second half
    if re.match(r'^[\w]{32}:[\w]{32}$',passwd):
        return binascii.unhexlify(passwd.split(':')[1])
        
    digest = hashlib.new('md4', passwd.encode('utf-16le')).digest()
    return digest

def create_NT_hashed_password_v2(passwd, user, domain):
    "create NT hashed password"
    digest = create_NT_hashed_password_v1(passwd)
    
    return hmac.new(digest, (user.upper()+domain).encode('utf-16le')).digest()
    return digest
    
def create_sessionbasekey(password):
    return hashlib.new('md4', create_NT_hashed_password_v1(password)).digest()

if __name__ == "__main__":
    def ByteToHex( byteStr ):
        """
        Convert a byte string to it's hex string representation e.g. for output.
        """
        return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )

    def HexToByte( hexStr ):
        """
        Convert a string hex byte values into a byte string. The Hex Byte values may
        or may not be space separated.
        """
        bytes = []

        hexStr = ''.join( hexStr.split(" ") )

        for i in range(0, len(hexStr), 2):
            bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

        return ''.join( bytes )
        
    ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
    ClientChallenge = '\xaa'*8
    Time = '\x00'*8
    Workstation = "COMPUTER".encode('utf-16-le')
    ServerName = "Server".encode('utf-16-le')
    User = "User"
    Domain = "Domain"
    Password = "Password"
    RandomSessionKey = '\55'*16
    assert HexToByte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d") == create_LM_hashed_password_v1(Password)                  # [MS-NLMP] page 72
    assert HexToByte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52") == create_NT_hashed_password_v1(Password)    # [MS-NLMP] page 73
    assert HexToByte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84") == create_sessionbasekey(Password)
    assert HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94") == calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge)
    assert HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13") == calc_resp(create_LM_hashed_password_v1(Password), ServerChallenge)
    
    (NTLMv1Response,LMv1Response) = ntlm2sr_calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge, ClientChallenge)
    assert HexToByte("aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00") == LMv1Response  # [MS-NLMP] page 75
    assert HexToByte("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32") == NTLMv1Response
    
    assert HexToByte("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f") == create_NT_hashed_password_v2(Password, User, Domain)    # [MS-NLMP] page 76
    ResponseKeyLM = ResponseKeyNT = create_NT_hashed_password_v2(Password, User, Domain)
    (NTLMv2Response,LMv2Response) = ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)
    assert HexToByte("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa") == LMv2Response  # [MS-NLMP] page 76
    
    # expected failure
    # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value given on page 77 (this suggests a mistake in the spec)
    #~ assert HexToByte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c") == NTLMv2Response, "\nExpected: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c\nActual:   %s" % ByteToHex(NTLMv2Response) # [MS-NLMP] page 77
    
