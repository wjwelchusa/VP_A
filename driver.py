# Port scanning w/o nmap utilities
# Joe Welch
# 8 Jan 2017
# Derived from Violent Python book, named "portScan.py"
# Original code worked from command line. This code adjusted to run as program accepted input.
# Due to differences between Windows and Linux. Code from text seems to work more directly in Linux than Windows.

# optparse not needed as command line input not used
# import optparse     # deprecated since python 3.2; no further development


#To do:
# 1. refine this project to incorporate python-nmap library
# 2. better inderstand screenLock and Semaphore
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)       #AF_INET = IPv4; SOCK_STREAM = TCP; refer to Python docs for more info
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print ("[+] %d/tcp open" % (tgtPort))
        print ("[+]"  + str(results))
    except:
        screenLock.acquire()
        print ("[-] %d/tcp closed" % (tgtPort))
    finally:
	    screenLock.release()
	    connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
        print(tgtHost)
        print(tgtIP)
    except:
        print ("[-] Cannot resolve %s: Unknown host" % (tgtHost))
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print ("\n[+] Scan Results for: " + tgtName[0])
    except:
        print ("\n[+] Scan Results for: " + tgtIP)

    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan,args=(tgtHost,int(tgtPort)))
        t.start()

def main():
    tgtHost = "www.microsoft.com"
    tgtPorts = ["22", "80", "443"]

    portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
    main()


