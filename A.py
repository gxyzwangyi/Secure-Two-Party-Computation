#!/usr/bin/python
 
import socket
import json

import base64
from pyDes import *
import random, string
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA


def socket_part():
    HOST='127.0.0.1'
    PORT=50007
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)       
    s.connect((HOST,PORT))       
    while 1:
        number=input("Please input number:")        
        binx=bin(number)
        length=len(binx)
        s.sendall("0"+str(length))
        # print "0"+str(length)
        data=s.recv(2048)
        # print data      
        diff=int(data[1::])
        if diff<0:
            real_diff=abs(diff)
            binx=binx[0:2]+real_diff*"0"+binx[2::]
        for j,i in enumerate(binx[2::]):
            result=xor(s,i)
            if result==1:
                print j, len( binx[ 2:: ] )
                if j == len( binx[ 2:: ] )-1:
                    print j, len( binx[2::])
                    get_result( s,1 )
                    break
                print "xor continue"
                continue
            elif result==0:
                compare(s,i)
                break
            else:
                print result
                print "something error"
    s.close()    





def xor(s,i):
    print "XOR"    
    key_list=gen_key()
    ttm_list=gen_ttm(i,key_list,0)
    ttm_str=list_to_str(ttm_list)
    s.sendall("1"+ttm_str)       
    data=s.recv(2048)      
    if data.startswith("1"):
        p_list=str_to_list(data[1::])
        p0=p_list[0]
        p1=p_list[1]
        yk_list=ot_message(p0,p1,key_list)
        yk_str=list_to_str(yk_list)
        s.sendall("2"+yk_str)
        data=s.recv(2048)      
        if data.startswith("2"):
            kw_list=str_to_list(data[1::])
            kw=kw_list[0]
            result=verify_k(key_list,kw)-4
            s.sendall( "3" + str( result ) )
            return result


def compare(s,i):
    print "compare"
    key_list=gen_key()
    ttm_list=gen_ttm(i,key_list,1)
    ttm_str=list_to_str(ttm_list)
    s.sendall("1"+ttm_str)       
    data=s.recv(2048)      
    if data.startswith("1"):
        p_list=str_to_list(data[1::])
        p0=p_list[0]
        p1=p_list[1]
        yk_list=ot_message(p0,p1,key_list)
        yk_str=list_to_str(yk_list)
        s.sendall("2"+yk_str)
        data=s.recv(2048)      
        if data.startswith("2"):
            kw_list=str_to_list(data[1::])
            kw=kw_list[0]
            result=verify_k(key_list,kw)-4 
            print "end"
            return get_result(s,result)



def list_to_str(x):
    result_list=[]
    for i in x:
        result_list.append(base64.b64encode(i))
    result=json.dumps(result_list)
    return result


def str_to_list(x):
    result_list=json.loads(x)
    result=[]
    for i in result_list:
        result.append(base64.b64decode(i))
    return result



def gen_ttm(x,key_list,mode):
    print mode
    tt=gen_tt(key_list,mode)
    ttm=tt_message(int(x),tt,key_list)
    return ttm 



def Encrypt(str,key="12345678"):
    Des_IV = "\0\0\0\0\0\0\0\0" 
    k = des(key, CBC, Des_IV, pad=None, padmode=PAD_PKCS5)
    EncryptStr = k.encrypt(str)
    return EncryptStr

def rand_string(n=8, a=string.hexdigits):
    return ''.join(random.choice(a) for i in range(n))

def permute(A):
    random.shuffle(A)
    return A

def gen_key():
    print "generate keylist"
    key_list=[]
    for i in range(6):
        key_list.append(rand_string())
    print key_list    
    return key_list


def gen_tt(key_list,mode):
    print "generate the true table"
    if mode==0:
        t1=Encrypt(Encrypt(key_list[5],key_list[2]),key_list[0])
        t2=Encrypt(Encrypt(key_list[4],key_list[3]),key_list[0])
        t3=Encrypt(Encrypt(key_list[4],key_list[2]),key_list[1])
        t4=Encrypt(Encrypt(key_list[5],key_list[3]),key_list[1])
        tt_list=[t1,t2,t3,t4]
        tt_list=permute(tt_list)
    else:
        t1=Encrypt(Encrypt(key_list[5],key_list[2]),key_list[1])
        t2=Encrypt(Encrypt(key_list[4],key_list[3]),key_list[1])
        t3=Encrypt(Encrypt(key_list[4],key_list[3]),key_list[0])
        t4=Encrypt(Encrypt(key_list[4],key_list[2]),key_list[0])
        tt_list=[t1,t2,t3,t4]
        tt_list=permute(tt_list)
    return tt_list


def tt_message(x,tt,key_list):
    print "add true table"
    if x==0:
        k0=key_list[0]
        ttm=tt+[k0]
        return ttm
    else:
        k1=key_list[1]
        ttm=tt+[k1]
        return ttm


# use publickey p0 p1 from bob to des ky0 ky1 
def ot_message(p0,p1,key):
    print "use public-key"
    en_key0 = RSA.importKey(p0)
    en_cipher0 = Cipher_pkcs1_v1_5.new(en_key0)
    cipher_text0 = en_cipher0.encrypt(key[2])
    en_key1 = RSA.importKey(p1)
    en_cipher1 = Cipher_pkcs1_v1_5.new(en_key1)
    cipher_text1 = en_cipher1.encrypt(key[3])
    c_list=[cipher_text0,cipher_text1]
    return c_list 

    


def verify_k(k_list,key):
    #print k_list.index(key)
    return k_list.index(key)


def get_result(s,result):
    s.sendall( "9" + str( result ) )
    if result==1:
        print "Alice biger or equals"
    elif result==0:
        print "Bob biger"
    else:
        print "i don't know" 


socket_part()
    




