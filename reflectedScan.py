from scan import *
import time
import re

def e(string):
        return string.encode('utf-8')

def d(string):
        return string.decode('utf-8')

url = input("entrez un url:")

scan = scan(url)
pageHtml = scan.getHtml2()

if pageHtml !=0:
    inputs = re.findall(r'(?i)(?s)<input.*?>',pageHtml)
    print(inputs)
    payloads = scan.getPayloadList()
    inputVul =[]
    i = 0
    for line in payloads:
        line =  line.decode("utf-8")
        for inp in inputs:
            if line.lower() in inp.lower():
                scan.vuln.append(line)
                status = 'positive'
                scan.saveVulnLinks()
                inpName = re.search(r'(?i)name=[\'"](.*?)[\'"]', inp)
                inpName = d(e(inpName.group(1)))
                inputVul.append(inpName)
            print('['+str(i)+']'+' test: '+line +' ---> '+status+' in input '+inpName)
            status = 'négative'
        i+=1
        time.sleep(0.05)
    print("------------------------------------resultats-------------------------------------------------")
    if len(scan.vuln) == 0:
        print('aucun XSS attaque n est trouvé')
        print("-----------------------------------------------------------------------------------------------")
    else :
        j = 0
        for vul in scan.vuln :
            print("Input: "+inputVul[j]+" is affected ---> "+vul)
            j+=1
        print("-----------------------------------------------------------------------------------------------")
    




