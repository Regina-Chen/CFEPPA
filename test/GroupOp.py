
#coding:utf-8
from pypbc import *
import rsa
import time
import RsaTest
import Schnorr 
import hashlib
import random

stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""

params = Parameters(param_string=stored_params)
pairing = Pairing(params)

g = Element.random(pairing,G2)
u = Element.random(pairing,G2)
a = Element.random(pairing,Zr)
N = random.randint(0,10000)
M = random.randint(0,10000)

BlsPK=Element(pairing,G2,value=g**a)
BlsH=Element(pairing,G2,value=u**a)


def BlsGen():
    b = Element.random(pairing,Zr)
    pk = Element(pairing,G2,value=g**a)
    return pk

def BlsSig():
    h = Element(pairing,G2,value=u**a)
    return h

def BlsVef(h,pk):
    
    
    if(pairing.apply(g,pk)==pairing.apply(u,h)):
        return True
    else:
        return False

def RsaZkPro():
    x = random.randint(0,10000)
    y = random.randint(0,10000)
    Yy= pow(y,x,N)
    Aa = pow(y,x,N)
    Cc=Aa * Yy
#    print(type(x))
#    print((Cc))

def RsaZkVef():
    x = random.randint(0,10000)
    y = random.randint(0,10000)
    Yy= pow(y,x,N)
    Aa = pow(y,x,N)
    


def ShnorrZkPro():
    w = Element.random(pairing,Zr)
    h = Element(pairing,G2,value=g**w)
    a1 = Element.random(pairing,Zr)
    Aa = Element(pairing,G2,value=g**a)
    z = Element(pairing,Zr,value=a*w+a1)

def ShnorrZkVef():
    c = Element.random(pairing,Zr)
    h = Element(pairing,G2,value=g**c)
    i = Element(pairing,G2,value=u**a)
    j = Element(pairing,G2,value=h*u)


def SetupZL():
    start = time.perf_counter()
    h = Element(pairing,G2,value=u**a)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    #j = Element(pairing,G2,value=g**a)
    end = time.perf_counter()
    print("Setup时间为:",end-start)
    return cip,pk

def LockZl():
    start = time.perf_counter()
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    G,Q,e,s,M=Schnorr.Shnorr_Enc()
    h=Element(pairing,G2,value=u**a)
    h=Element(pairing,G2,value=u**a)
    h=Element(pairing,G2,value=u**a)
    j=Element(pairing,G2,value=u*g)
    j=Element(pairing,G2,value=u*j)
    i=Element(pairing,G2,value=u+g)
    i=Element(pairing,G2,value=u+i)
    i=Element(pairing,G2,value=u+i)
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    end = time.perf_counter()
    print("Lock时间为:",end-start)
    return G,Q,e,s,M

def ReZl(cip,pk,G,Q,e,s,M):
    start = time.perf_counter()
    i=Element(pairing,G2,value=u+g)
    content = RsaTest.rsaDecrypt(cip, pk)
    Schnorr.Shnorr_Dnc(G,Q,e,s,M)
    end = time.perf_counter()

    print("Re时间为:",end-start)
    
def Puzzlepromise():    
    start = time.perf_counter()
    r = random.randint(0,2^256)
    r = random.randint(0,2^256)    
    h = Element(pairing,G2,value=u*g)
    h = Element(pairing,G2,value=u*g)
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    r = random.randint(0,2^256)    
    h = Element(pairing,G2,value=u*g)
    z = Element(pairing,G2,value=u+g)
    z = Element(pairing,G2,value=u+z)
    h = Element(pairing,G2,value=u*g)
    z = Element(pairing,G2,value=u+g)
    z = Element(pairing,G2,value=u+z)
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    z = Element(pairing,G2,value=u+g)
    z = Element(pairing,G2,value=u+z)
    end = time.perf_counter()
    t = end-start
    print("promise时间为:",t)
    return t
    
def Puzzlesolve():
    start = time.perf_counter()
    r = random.randint(0,2^256)
    r = random.randint(0,2^256)    
    z = Element(pairing,G2,value=u+g)
    z = Element(pairing,G2,value=u+g)
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    z = Element(pairing,G2,value=u+g)
    h = Element(pairing,G2,value=u*g)
    h = Element(pairing,G2,value=u*g)
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    z = Element(pairing,G2,value=u+g)
    z = Element(pairing,G2,value=u+g)
    r = r+r
    r = r+r
    r = r+r
    r = r*r
    end = time.perf_counter()
    t = end-start
    print("solve时间为:",t)
    return t
    
    

def SetupAmhl(n):
    start = time.perf_counter()
    for i in range(1,n):
        ShnorrZkPro()
        ShnorrZkVef()
        h = Element(pairing,G2,value=u*g)
        j = Element(pairing,G2,value=u*h)
        z = Element(pairing,G2,value=u+g)
        z = Element(pairing,G2,value=u+z)
    x = Element(pairing,G2,value=u*g)
    end = time.perf_counter()
    print("Setup时间为:",end-start)

def LockAmhl():
    start = time.perf_counter()
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkPro()
    ShnorrZkVef()
    G,Q,e,s,M=Schnorr.Shnorr_Enc()
    
    j=Element(pairing,G2,value=u*g)
    j=Element(pairing,G2,value=u*j)
    j=Element(pairing,G2,value=u*j)
    j=Element(pairing,G2,value=u*j)
    j=Element(pairing,G2,value=u*j)
    j=Element(pairing,G2,value=u*j)

    i=Element(pairing,G2,value=u+g)
    i=Element(pairing,G2,value=u+i)
    i=Element(pairing,G2,value=u+i)
    i=Element(pairing,G2,value=u+i)
    i=Element(pairing,G2,value=u+i)
    i=Element(pairing,G2,value=u+i)

    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))

    end = time.perf_counter()
    print("Lock时间为:",end-start)
    return G,Q,e,s,M

def ReAmhl(G,Q,e,s,M):
    start = time.perf_counter()
    i=Element(pairing,G2,value=u+g)
    i=Element(pairing,G2,value=u+i)
    j=Element(pairing,G2,value=u*g)
    j=Element(pairing,G2,value=u*j)
    Schnorr.Shnorr_Dnc(G,Q,e,s,M)
    end = time.perf_counter()
    print("Re时间为:",end-start)

def SetupLokeable():
    start = time.perf_counter()
    pk1=BlsGen()
    pk1=BlsGen()
    pk1=BlsGen()
    ShnorrZkPro()
    ShnorrZkPro()
    ShnorrZkPro()
    ShnorrZkVef()
    ShnorrZkVef()
    j=Element(pairing,G2,value=u*g)
    cip, pk = RsaTest.rsaEncrypt('hello world')
    content = RsaTest.rsaDecrypt(cip, pk)
    cip, pk = RsaTest.rsaEncrypt('hello world')
    content = RsaTest.rsaDecrypt(cip, pk)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    content = RsaTest.rsaDecrypt(cip, pk)
    h=BlsSig()
    BlsVef(h,pk1)
    end = time.perf_counter()
    print("Setup时间为:",end-start)

def LockLokeable():
    start = time.perf_counter()
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    h=BlsSig()
    h=BlsSig()
    h=BlsSig()
    b=pairing.apply(g,u)
    c=pairing.apply(g,u)
    i = Element(pairing,GT,value=b*c)
    b=pairing.apply(g,u)
    c=pairing.apply(g,u)
    i = Element(pairing,GT,value=b*c)
    b=pairing.apply(g,u)
    c=pairing.apply(g,u)
    i = Element(pairing,GT,value=b*c)
    end = time.perf_counter()
    print("Lock时间为:",end-start)

def ReLockable():
    start = time.perf_counter()
    b=pairing.apply(g,u)
    c=pairing.apply(g,u)
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    end = time.perf_counter()
    print("Re时间为:",end-start)

def SetupGq():
    start = time.perf_counter()
    (pubkey, privkey) = rsa.newkeys(512)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    #j = Element(pairing,G2,value=g**a)
    RsaZkPro()
    RsaZkVef()
    end = time.perf_counter()
    print("Setup时间为:",end-start)
    return cip,pk
    
def CrossInit():
    start = time.perf_counter()
    (pubkey, privkey) = rsa.newkeys(512)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha1val = sha1obj.hexdigest()
    sha = int(sha1val,16)
#    print(sha1val)
    r1 = random.randint(0,2^256)
    beta = r1*r1^sha
    cip, pk = RsaTest.rsaEncrypt("hello world")
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha1val = sha1obj.hexdigest()
    sha = int(sha1val,16)
    r2 = random.randint(0,2^256)
    beta = r2*r2^sha
    end = time.perf_counter()
    t = end-start
    print("Setup时间为:",t)
    return t
    
def CrossLock():
    start = time.perf_counter()
    (pubkey, privkey) = rsa.newkeys(512)
    r = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    r = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    rr = r*r*r
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha1val = sha1obj.hexdigest()
    sha = int(sha1val,16)
    beta = r*r^sha
    rr = r*r*r
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    beta = r*r^sha
    b = beta*beta
    
    r = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    r = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    rr = r*r*r
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha1val = sha1obj.hexdigest()
    sha = int(sha1val,16)
    beta = r*r^sha
    rr = r*r*r
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha1val = sha1obj.hexdigest()
    sha = int(sha1val,16)
    beta = r*r^sha
    b = beta*beta
    
    end = time.perf_counter()
    t = end-start
    print("Lock时间为:",t)
    return t
    
def CrossRel():
    r = random.randint(2,2^256)
    start = time.perf_counter()
    r = r*r
    r = r/r
    r = r*r
    end = time.perf_counter()
    t = end-start
    print("Re时间为:",t)
    return t
    
def LockGq():
    start = time.perf_counter()
    #(pubkey, privkey) = rsa.newkeys(512)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    content = RsaTest.rsaDecrypt(cip, pk)
    content = RsaTest.rsaDecrypt(cip, pk)
    content = RsaTest.rsaDecrypt(cip, pk)
    RsaZkPro()
    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    sha2obj = hashlib.sha1()
    sha2obj.update("Hello,world".encode("utf-8"))
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    
    c = N*M
    c = N*M
    end = time.perf_counter()
    print("Lock时间为:",end-start)

def ReGq(cip, pk):
    start = time.perf_counter()
    content = RsaTest.rsaDecrypt(cip, pk)
    c =15245573/548221
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    end = time.perf_counter()
    print("Re时间为:",end-start)

def CrossPromise1():
    start = time.perf_counter()
    (pubkey, privkey) = rsa.newkeys(512)
    r1 = random.randint(0,2^256)
    r1 = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
#    RsaZkPro()
#    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    r1 = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r = r1*r1*r1
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r = r*r*r
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r = r*r
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    end = time.perf_counter()
    t = end-start
    print("CrossPromise1时间为:",t)
    return t
    
def CrossPromise2():
    start = time.perf_counter()    
    r1 = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    RsaZkPro()
    RsaZkVef()
    r1 = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r1 = random.randint(0,2^256)
    cip, pk = RsaTest.rsaEncrypt("hello world")
    RsaZkPro()
    RsaZkVef()
    r = r1*r1*r1
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    cip, pk = RsaTest.rsaEncrypt("hello world")
    sha1obj = hashlib.sha1()
    sha1obj.update("Hello,world".encode("utf-8"))
    r = r*r*r
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world")
    r = r*r
    end = time.perf_counter()
    t = end-start
    print("CrossPromise2时间为:",t)
    return t
    
def CrossSolve():
    start = time.perf_counter()
    cip, pk = RsaTest.rsaEncrypt("hello world")
    cip, pk = RsaTest.rsaEncrypt("hello world155555555555555555555555555555555555")
#    print(type(cip))
#    print(len(cip))
    print("[+]------------------------------------")
    RsaZkPro()
    r = 57455792089393086466858745825606470592500089351915344541057675028242968457750
    r = r*r
    end = time.perf_counter()
    t = end-start
    print("CrossSolve时间为:",t)
    return t
    
def VTSCommit():
    start = time.perf_counter()
    sigma = 123456789
    N = 57455792089393086466858745825606470592500089351915344541057675028242968457750
    k = random.randint(2^128,2^256)
    a = random.randint(2^128,2^256)
    C = sigma^k
    u = 1
    for i in range(0,256):
        u = u*2%N
        b = a^u%N
    Ck = k+b %N
    end = time.perf_counter()
    t = end-start
    print("VTScommit时间为:",t)
    return t

def VTSVerify():
    sigma = 123456789
    N = 57455792089393086466858745825606470592500089351915344541057675028242968457750
    k = random.randint(2^128,2^256)
    a = random.randint(2^128,2^256)
    C = sigma^k
    start = time.perf_counter()
    u = 1
    for i in range(0,256):
        u = u*2%N
        b = a^u%N
    Ck = k+b %N
    sigma = C^k
    end = time.perf_counter()
    t = end-start
    print("VTSverify时间为:",t)
    return t



if __name__ == "__main__":
#    cip,pk=SetupZL()
#    G,Q,e,s,M=LockZl()
#    ReZl(cip,pk,G,Q,e,s,M)

#    SetupAmhl(2)
#    G,Q,e,s,M=LockAmhl()
#    ReAmhl(G,Q,e,s,M)

#    SetupLokeable()
#    LockLokeable()
#    ReLockable()

#    cip,pk=SetupGq()
#    LockGq()
#    ReGq(cip,pk)
#    t = CrossSolve()
#    t = VTSCommit()
    
 
    print("[+]cy-------------------------")
    sum = 0
    for i in range(1,1000):
#        t = CrossInit()
#        t = CrossLock()
#        t = CrossRel()
#        t = Puzzlepromise()
#        t = Puzzlesolve()
        t = CrossPromise1()
#        t = CrossPromise2()
#        t = CrossSolve()
#        t = VTSVerify()
        sum = sum+t
    a = sum / 1000
    print(a)

