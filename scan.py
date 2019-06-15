import urllib.request as urllib2
import os
import sys

class scan():

    def __init__(self, url):
        self.vuln = []
        self.url = url   

    def getHtml(self):
        if not self.url.startswith('http'):
            self.url = 'https://'+self.url
        self.response = urllib2.urlopen(self.url)
        self.pageCode = self.response.read()
        return self.pageCode


    def getPayloadList(self):
        if os.path.isfile("payload.txt") :
            self.payload = open("payload.txt",'rb')
            self.payloadLines = [line.strip() for line in self.payload.readlines()]
            return self.payloadLines
        else :
            print('le fichier payload n existe pas')
    

    
    def saveVulnLinks(self):
        f = open('report.txt', 'w+')
        i = 0
        while i != len(self.vuln):
            f.write(self.vuln[i].decode('utf-8') + "\n")
            i = i + 1
        f.close()
        print("Fin.....")
    
