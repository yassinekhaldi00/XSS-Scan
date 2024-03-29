import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
import time
from scan import * 

class Window(QWidget):

    def __init__(self):
        super().__init__()
        self.left = 300
        self.top = 100
        self.width = 800
        self.height = 500

        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setWindowTitle('Xss detection')

        self.l = QLabel('URL :',self)
        self.input = QLineEdit(self)
        self.input.setFixedWidth(600)
        self.sc = QPushButton('Scan',self)
        self.sc.setFixedWidth(80)
        self.nw = QPushButton('New', self)
        self.nw.setFixedWidth(80)
        self.message = QTextEdit(self)
        self.message.setReadOnly(True)
        self.l1 = QLabel('Reslutats',self)
        self.result = QTextEdit(self)
        self.result.setReadOnly(True)
        self.result.setFixedHeight(100)

        self.scanChoice = QGroupBox()
        self.lightScan = QRadioButton("Light scan")
        self.fullScan = QRadioButton("Full scan")
        self.lightScan.setChecked(True)

        h3_box = QHBoxLayout()
        h3_box.addStretch()
        h3_box.addWidget(self.lightScan)
        h3_box.addWidget(self.fullScan)
        h3_box.addStretch()

        h_box = QHBoxLayout()
        h_box.addStretch()
        h_box.addWidget(self.l)
        h_box.addWidget(self.input)
        h_box.addStretch()

        h1_box = QHBoxLayout()
        h1_box.addStretch()
        h1_box.addWidget(self.sc)
        h1_box.addWidget(self.nw)
        h1_box.addStretch()

        h2_box = QHBoxLayout()
        h2_box.addStretch()
        h2_box.addWidget(self.l1)
        h2_box.addStretch()

        v_box = QVBoxLayout()
        v_box.addLayout(h_box)
        v_box.addLayout(h3_box)
        v_box.addLayout(h1_box)
        v_box.addWidget(self.message)
        v_box.addLayout(h2_box)
        v_box.addWidget(self.result)

        self.setLayout(v_box)

        self.sc.clicked.connect(self.scn)
        self.nw.clicked.connect(self.new)

        self.show()

        self.start = True
    
    def scn(self):
        if self.input.text() == '':
            errorBox = QMessageBox.critical(self, 'Erreur, case vide!!!', 'Entrez un URL.')
            self.start = False

        elif self.input.text()[:8] != 'https://' and self.input.text()[:7] != 'http://':
            errorBox = QMessageBox.critical(self,"Erreur, URL invalide!! ","Ajoutez https:// ou http:// au début de l'URL ")
            self.start = False   

        else:
            self.scan = scan(self.input.text())
            pageHtml = self.scan.getHtml2()
            self.start = True

        
        if self.start and self.scan.dection_firewall(pageHtml) :
            msgBox = QMessageBox.question(self,'Firewall detecté!!', ' Voulez contuniez votre scan ?',QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if msgBox == QMessageBox.Yes:
                if pageHtml != None :

                    if self.lightScan.isChecked:
                        payloadList = self.scan.getPayloadList("payload.txt")
                    else:
                        payloadList = self.scan.getPayloadList("payload2.txt")
                    
                    i = 0
                    status ='négative'

                    for line in payloadList :
                        line =  line.decode("utf-8")

                        if line.lower() in pageHtml.lower():
                            self.scan.vuln.append(line)
                            status = 'positive'
                            self.scan.saveVulnLinks()

                        self.message.append('['+str(i)+']'+' test: '+line +' ---> '+status)
                        status = 'négative'
                        i+=1

                    if len(self.scan.vuln) == 0:
                        self.result.append("Aucun XSS attaque n'est trouvé")

                    else :
                        self.result.append("resultats: "+len(self.scan.vuln))
                        self.result.append("-----------------------------------------")
                        for vul in self.scan.vuln :
                            self.result.append(vul[1:])
                
                else: 
                    errorBox = QMessageBox.critical(self, 'Erreur, URL invalid!!', 'Entrez un URL valid.')
            
        elif self.start:
            if pageHtml != None :

                if self.lightScan.isChecked():
                    payloadList = self.scan.getPayloadList("payload.txt")
                else:
                    payloadList = self.scan.getPayloadList("payload2.txt")

                i = 0
                status ='négative'

                for line in payloadList :
                    line =  line.decode("utf-8")

                    if line.lower() in pageHtml.lower():
                        self.scan.vuln.append(line)
                        status = 'positive'
                        self.scan.saveVulnLinks()

                    self.message.append('['+str(i)+']'+' test:  '+line +' ---> '+status)
                    status = 'négative'
                    i+=1

                if len(self.scan.vuln) == 0:
                    self.result.append("Aucun XSS attaque n'est trouvé")

                else :
                    self.result.append("resultats: "+str(len(self.scan.vuln))+" injections")
                    self.result.append("-----------------------------------------")
                    for vul in self.scan.vuln :
                        self.result.append(vul[1:])
            
            else:
                errorBox = QMessageBox.critical(self, 'Erreur, URL invalid!!', 'Entrez un URL valid.')
        

    
    def new(self):
        self.input.setText('')
        self.message.setText('')
        self.result.setText('')
        self.scan = None




app = QApplication(sys.argv)
a_window = Window()
sys.exit(app.exec_())