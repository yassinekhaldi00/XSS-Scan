import urllib.request as urllib2
import os
import sys
import requests
from user_agent import generate_user_agent # generation d'un random web utilisateur valid


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
    
    def getHtml2(self):
        session = requests.Session()
        response = self.read_response(session, self.url)
        print(response.text)
        return response.text


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
            f.write(self.vuln[i] + "\n")
            i = i + 1
        f.close()
        print("Fin.....")
    
    def read_response(self, session, url):
        headers = {'User-Agent': generate_user_agent(device_type="desktop", os=('mac', 'linux'))}
        # The Session object allows you to persist certain parameters across requests	
        page_response = session.get(url, headers=headers) 

		# Detect a Web Application Firwall.
        return page_response
	