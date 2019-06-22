from scan import *
import time

url = input("entrez un url:")

scan = scan(url)

pageHtml = scan.getHtml2()
if pageHtml != None :
    payloadList = scan.getPayloadList()
    i = 0
    status ='négative'
    for line in payloadList :
        line =  line.decode("utf-8")
        if line.lower() in pageHtml.lower():
            scan.vuln.append(line)
            status = 'positive'
            scan.saveVulnLinks()
        print('['+str(i)+']'+' test: '+line +' ---> '+status)
        status = 'négative'
        i+=1
        time.sleep(0.05)
    print("------------------------------------resultats-------------------------------------------------")
    if len(scan.vuln) == 0:
        print('aucun XSS attaque n est trouvé')
        print("-----------------------------------------------------------------------------------------------")
    else :
        for vul in scan.vuln :
            print(vul)
        print("-----------------------------------------------------------------------------------------------")
    
        

