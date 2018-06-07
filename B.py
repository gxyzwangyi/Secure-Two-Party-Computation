#!/usr/bin/python
 
import socket   
import commands   
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from pyDes import *
import json
import base64



def socket_part():
	HOST='127.0.0.1'
	PORT=50007
	s= socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
	s.bind((HOST,PORT))    
	s.listen(1)          
	while 1:
		conn,addr=s.accept()    
		#print'Connected by',addr     
		while 1:
			number=input("Please input number:")   
			binx=bin(number)
			length=len(binx)
			print length
			data=conn.recv(2048)
			print data
			A_length=int(data[1::])
			diff=A_length-length
			if diff>0:
				binx=binx[0:2]+diff*"0"+binx[2::]
				conn.sendall("0"+str(diff))
			else:
				conn.sendall("0"+str(diff))
			for j,i in enumerate(binx[2::]):
				result=xor(conn,i)
				if result==1:
					if j == len( binx[ 2:: ] )-1 :
						get_result( conn )
						break
					print "xor continue"
					continue
				elif result==0:
					compare(conn,i)
					break
				else:
					print result
					print "something error"
					
	conn.close()      






    
    


def xor(conn,i):
    print "XOR"
    data=conn.recv(2048)       
    if data.startswith("1"):
		rsa_list=gen_rsa()
		ttm_list=str_to_list(data[1::])
		sp_list=ot_message(int(i),rsa_list)
		message_list=[sp_list[2],sp_list[3]]
		message_str=list_to_str(message_list)
		conn.sendall("1"+message_str)
		data=conn.recv(2048)       
		if data.startswith("2"):
			yk_list=str_to_list(data[1::])
			c0=yk_list[0]
			c1=yk_list[1]
			s0=sp_list[0]
			s1=sp_list[1]
			# print yk_list
			y0=get_ot_message(s0,s1,c0,c1,i)  
			kw=de_tt(ttm_list,y0)
			kw_str=list_to_str([kw])
			conn.sendall("2"+kw_str)
			data=conn.recv(2048) 
			if data.startswith("3"):
				result=int(data[1::])
				return result



def compare(conn,i):
    print "compare"
    data=conn.recv(2048)       
    if data.startswith("1"):
        rsa_list=gen_rsa()
        ttm_list=str_to_list(data[1::])
        rsa_key=gen_rsa()
        sp_list=ot_message(int(i),rsa_list)
        message_list=[sp_list[2],sp_list[3]]
        message_str=list_to_str(message_list)
        conn.sendall("1"+message_str)
        data=conn.recv(2048)       
        if data.startswith("2"):
            yk_list=str_to_list(data[1::])
            c0=yk_list[0]
            c1=yk_list[1]
            s0=sp_list[0]
            s1=sp_list[1]
            y0=get_ot_message(s0,s1,c0,c1,i)  
            kw=de_tt(ttm_list,y0)
            kw_str=list_to_str([kw])
            conn.sendall("2"+kw_str)
            get_result(conn)



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



def Decrypt(str,key="12345678"):
    # try:
	Des_IV = "\0\0\0\0\0\0\0\0" 
	k = des(key, CBC, Des_IV, pad=None, padmode=PAD_PKCS5)
	DecryptStr = k.decrypt(str)
	return DecryptStr
    # except Exception,e:
	# 	print "----------------------"
	# 	print e
	# 	return "0"


def ot_message(x,rsa_key):
    print "generate ot"
    s1_key=rsa_key[0]
    p1_key=rsa_key[1]
    s2_key=rsa_key[2]
    p2_key=rsa_key[3]

    if x==0:
		s0=s1_key
		s1=s2_key
		p0=p1_key
		p1=p2_key
		list=[s0,s1,p0,p1]
		return list	
    else:
		s0=s2_key
		s1=s1_key
		p0=p2_key
		p1=p1_key
		list=[s0,s1,p0,p1]
		return list




#get ky from Alice 
def get_ot_message(s0,s1,c0,c1,x):
    print "decrypt ot"
    #print s0,s1
    try:
		de_key0 = RSA.importKey(s0)
		de_cipher0 = Cipher_pkcs1_v1_5.new(de_key0)
		text = de_cipher0.decrypt(c0, random_generator)
		print "0"
		print text
		return text
    except Exception,e:
        print "0e"
        print e
        
    try:
		de_key1 = RSA.importKey(s1)
		de_cipher1 = Cipher_pkcs1_v1_5.new(de_key1)
		text = de_cipher1.decrypt(c1, random_generator)
		#print "1"
		#print text
		return text
    except Exception,e:
    	print "1e"
        print e
		

def get_result(conn):
	data = conn.recv( 2048 )
	if data.startswith( "9" ):
		result = int( data[ 1:: ] )
		print "end"
		if result==1:
			print "Alice biger or equals"
		elif result==0:
			print "Bob biger"
		else:
			print "i don't know"


	
def de_tt(tt,ot):
    print "decrypt true table"
    x0=tt[-1]
    y0=ot
    print "++++"
    print x0
    print y0
    print len(tt[0]),len(tt[1]),len(tt[2]),len(tt[3])
    print len(Decrypt(tt[0],x0)),len(Decrypt(tt[1],x0)),len(Decrypt(tt[2],x0)),len(Decrypt(tt[3],x0))
    k1=Decrypt(Decrypt(tt[0],x0),y0)
    k2=Decrypt(Decrypt(tt[1],x0),y0)
    k3=Decrypt(Decrypt(tt[2],x0),y0)
    k4=Decrypt(Decrypt(tt[3],x0),y0)
    print "======"
    print k1,k2,k3,k4
    for i in [k1,k2,k3,k4]:
        if len(i)==8:
            return i 	


def gen_rsa():
    print "generate rsa key"
    rsa = RSA.generate(1024, random_generator)
    s1_key = rsa.exportKey()
    p1_key = rsa.publickey().exportKey()
    #real public fake pravite
    rsa1 = RSA.generate(1024, random_generator)

    s2_real_key = rsa1.exportKey()
    p2_real_key = rsa1.publickey().exportKey()

    s2_key = s2_real_key[::-1]
    p2_key = p2_real_key
    rsa_list=[s1_key,p1_key,s2_key,p2_key]
    return rsa_list














random_generator = Random.new().read
socket_part()
		


