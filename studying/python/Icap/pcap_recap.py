#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
pcap处理部分
'''

import sys 
import os 
import time
import struct 
from ctypes import windll 
from ctypes import * 

def genPcapFileHead(SnapLen): 
    rHeadInfo = b'\xa1\xb2\xc3\xd4'     # magic(DWORD)
    rHeadInfo += b'\x00\x02'            # version(WORD)
    rHeadInfo += b'\x00\x04'            # version(WORD)
    rHeadInfo += b'\x00\x00\x00\x00'    # thiszone(DWORD)
    rHeadInfo += b'\x00\x00\x00\x00'    # Sigfigs(DWORD)
    #rHeadInfo += struct.pack('!I',SnapLen) 
    rHeadInfo += b'\x00\x00\xff\xff'    # SnapLen(DWORD)
    rHeadInfo += b'\x00\x00\x00\x01'    # linktype(DWORD)
    return rHeadInfo

def genPcapFrameHead(Htimestamp,Ltimestamp,CapLen,Len): 
    rHeadInfo = struct.pack('I',Htimestamp)   # dwGMTime 1970以来秒数 (DWORD)
    rHeadInfo += struct.pack('I',Ltimestamp)  # dwMicroTime 毫秒数 (DWORD)
    rHeadInfo += struct.pack('I',CapLen)      # 头长度   =IP+MACLEN (DWORD)
    rHeadInfo += struct.pack('I',Len)         # 报文长度 =IP+MACLEN (DWORD)
    return rHeadInfo 

def genGtpV1Head(wLen): 
    '''
    BITS  btPnFlag:1;  //N-PDU Num   0
    BITS  btSeqFlag:1; //0
    BITS  btExFlag:1;  //0
    BITS  btSpare:1;   //0
    BITS  btPt:1;      //0
    BITS  btVersion:3; //1
    BYTE  bMsgType;    //255
    WORD  wLen;        //GTP头长度，包含扩展头和后面跟的ip报文长度
    WORD32 dwTeid;
    '''
    rHeadInfo = b'\x20'
    rHeadInfo += b'\xff'
    rHeadInfo += struct.pack('!H',wLen)
    rHeadInfo += struct.pack('!I',1234)
    return rHeadInfo 

def genUdpHead(wLen): 
    '''
    WORD16 wSrcPort;
    WORD16 wDstPort;
    WORD16 wLen;
    WORD16 wChkSum; //0
    '''
    rHeadInfo = struct.pack('!H',2152)
    rHeadInfo += struct.pack('!H',2152)
    rHeadInfo += struct.pack('!H',wLen)
    rHeadInfo += struct.pack('!H',0)
    return rHeadInfo 

def genIPv4Head(wPktLen,wId,wChkSum): 
    '''
    BITS  btVersion:4;  //4
    BITS  btHeadLen:4;  //5
    BYTE  bTos;     //dscp,0xff
    WORD16 wPktLen; //pktLen+ipheadlen
    WORD16 wId;     //++
    WORD16 wOffSet; //0
    BYTE   bTtl;    //0x80
    BYTE   bPro;    //UDP:8
    WORD16 wChkSum;
    T_IPV4 tSrcIp;
    T_IPV4 tDstIp;
    '''
    rHeadInfo = b'\x45'
    rHeadInfo += b'\xff'
    rHeadInfo += struct.pack('!H',wPktLen)
    rHeadInfo += struct.pack('!H',wId)
    rHeadInfo += struct.pack('!H',0)
    rHeadInfo += b'\x80'
    rHeadInfo += struct.pack('B',17)
    rHeadInfo += struct.pack('@H',wChkSum)
    rHeadInfo += b'\x01\x02\x03\x04'
    rHeadInfo += b'\x05\x06\x07\x08'
    return rHeadInfo 

def bytes2int(bytes):
    #return int(str.encode('hex'), 16)  #py2.x??
    return int.from_bytes(bytes, byteorder='little')


PCAP_FILEHEAD_LEN  = 24
PCAP_FRAMEHEAD_LEN = 16
PCAP_MACHEAD_LEN   = 14
PCAP_IPHEAD_LEN    = 20
PCAP_GTPHEAD_LEN   = 8
PCAP_UDPHEAD_LEN   = 8


def insertTunnelHeads(pktinfile, pktoutfile):
    fin = open(pktinfile,'rb') 
    startPos = fin.tell() 
    fin.seek(0,os.SEEK_END) 
    endPos = fin.tell() 
    fin.seek(os.SEEK_SET) 
    fout = open(pktoutfile,'wb') #用二进制的写入模式 

    fout.write(fin.read(PCAP_FILEHEAD_LEN)) 

    chksumlibc1 = windll.LoadLibrary("chksumcalc_x64.dll") 
    #print(dir(libc1))
    wIPId = 0
    while(fin.tell() < endPos):
        Htimestamp = bytes2int(fin.read(4))
        Ltimestamp = bytes2int(fin.read(4))
        FrameCapLen = bytes2int(fin.read(4))
        FrameLen = bytes2int(fin.read(4)) - PCAP_MACHEAD_LEN
        wIPId += 1
        #print(FrameLen)
        tIPv4Head  = genIPv4Head((PCAP_IPHEAD_LEN+PCAP_UDPHEAD_LEN+PCAP_GTPHEAD_LEN+FrameLen),wIPId,0)
        #ctype_tIPv4Head = c_char_p(tIPv4Head) 
        ipv4chksum_c = c_ushort(chksumlibc1.geIPv4ChkSum(tIPv4Head))
        tIPv4Head  = genIPv4Head((PCAP_IPHEAD_LEN+PCAP_UDPHEAD_LEN+PCAP_GTPHEAD_LEN+FrameLen),wIPId,ipv4chksum_c.value)
        tUdpHead   = genUdpHead(FrameLen+PCAP_UDPHEAD_LEN+PCAP_GTPHEAD_LEN)
        tGtpV1Head = genGtpV1Head(FrameLen)
        FrameCapLenNew = FrameCapLen+PCAP_IPHEAD_LEN+PCAP_UDPHEAD_LEN+PCAP_GTPHEAD_LEN
        tPcapFrameHead = genPcapFrameHead(Htimestamp,Ltimestamp,FrameCapLenNew,FrameCapLenNew)

        fout.write(tPcapFrameHead)
        fout.write(fin.read(PCAP_MACHEAD_LEN))
        fout.write(tIPv4Head)
        fout.write(tUdpHead)
        fout.write(tGtpV1Head)
        fout.write(fin.read(FrameCapLen-PCAP_MACHEAD_LEN))

    fin.close() 
    fout.close()


if __name__ == '__main__': 
#tPcapFileHead = genPcapFileHead(255)
#print(type(PcapFileHeadInfo),sys.getsizeof(PcapFileHeadInfo),repr(PcapFileHeadInfo))
#tPcapFrameHead = genPcapFrameHead(0,0,10,11)
#tIPv4Head = genIPv4Head(wPktLen,wId,0)
    starttime = time.time()
    insertTunnelHeads('pkts_in.pcap', 'pkts_out.pcap')
    endtime = time.time()
    print("eclipse time:",endtime-starttime)