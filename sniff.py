#!/usr/local/bin/python2.7
## Import Scapy module
from scapy.all import *
from Queue import Queue
from threading import Thread
import time
import urllib2
import urllib
import socket
import re

q = Queue(maxsize=0)
num_threads = 1
url = 'http://localhost:8086/write?db=network_traffic&u=root&p=root'

def pushInfluxdb(q):
    while True:
        body = []
        size = q.qsize()
        #print "Queue: "+str(size)+"\n"
        if size > 100:
            for x in range(100):
                body.append(q.get())
            bodyString = "\n".join(body)
            try:
                request = urllib2.Request(url, bodyString)
                response = urllib2.urlopen(request)
                q.task_done()
            except:
                print "Influxdb down maybe"

def pkt_callback(packet):
    timeCalc = int(time.time())
    try:
        proto = packet[0][1].proto
        if proto == 1:
           proto = 'icmp'
        elif proto == 2:
           proto = 'igmp'
        elif proto == 4:
           proto = 'IPv4'
        elif proto == 6:
           proto = 'TCP'
        elif proto == 17:
           proto = 'UDP'
    except:
        proto = "N/A"

    # Get port information
    try:
        sport = packet[0][2].sport
        dport = packet[0][2].dport
    except:
        sport = 0
        dport = 0
    
    # Block unneeded shit
    if dport != 8086 and sport != 8086 and dport != 22 and sport != 22 and dport != 563:
        data = 'traffic,src='+packet[0][1].src+',dst='+packet[0][1].dst+',proto='+str(proto)+',sport='+str(sport)+',dport='+str(dport)+' value='+str(packet[0][1].len)+' '+str(timeCalc)+'000000000'
        q.put(data)   
        print "Queue: "+str(q.qsize()) +" Adding: "+data

for i in range(num_threads):
    worker = Thread(target=pushInfluxdb, args=(q,))
    worker.setDaemon(True)
    worker.start()

sniff(prn=pkt_callback, filter="ip", store=0)
q.join()


    #return "Packet len=%s,proto=%s,src=%s,dst=%s,sport=%s,dport=%s,time=%s" % (packet[0][1].len, proto, packet[0][1].src, packet[0][1].dst, sport, dport, timeCalc)

