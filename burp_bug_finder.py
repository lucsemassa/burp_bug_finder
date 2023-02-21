from burp import IBurpExtender
from burp import ITab
from java.io import PrintWriter
from burp import IProxyListener
from threading import Thread
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

import urllib

XSS_payload = '1"onmouseover=hihey(97912)"'
SQLi_payload = "'"
SQLi_message_trigger='You have an error in your SQL syntax'


class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, ITab, IMessageEditorController, AbstractTableModel):
    
    def processit(self, requestString, messageInfo=None):
        analyzed = self._helpers.analyzeRequest(messageInfo)
        parameters = analyzed.getParameters()
        
        modified_request=[]
        global XSS_payload
        global SQLi_payload
        global SQLi_message_trigger
        count_url_param = 0
        
        if (self._callbacks.isInScope(analyzed.getUrl())):

            first_req = []
            for i in range (0, len(parameters)) :
                if(parameters[i].getType()==parameters[i].PARAM_URL):
                    count_url_param = count_url_param + 1

                if(i==0):
                    modified_parameter = self._helpers.buildParameter(parameters[i].getName(), parameters[i].getValue(), parameters[i].getType())            
                    new_req=messageInfo.getRequest()
                    first_req = self._helpers.updateParameter(new_req, modified_parameter)
                    

                modified_parameter = self._helpers.buildParameter(parameters[i].getName(), parameters[i].getValue()+urllib.quote(XSS_payload), parameters[i].getType())            
                new_req=messageInfo.getRequest()
                new_req = self._helpers.updateParameter(new_req, modified_parameter)
                modified_request.append(new_req)

                modified_parameter = self._helpers.buildParameter(parameters[i].getName(), parameters[i].getValue()+urllib.quote(SQLi_payload), parameters[i].getType())            
                new_req=messageInfo.getRequest()
                new_req = self._helpers.updateParameter(new_req, modified_parameter)
                modified_request.append(new_req)

            if (count_url_param == 0):
                new_parameter = self._helpers.buildParameter("added", urllib.quote(XSS_payload), 0)  
                new_req=messageInfo.getRequest()
                new_req = self._helpers.addParameter(new_req, new_parameter)
                modified_request.append(new_req)
                #print(new_parameter.getName(),new_parameter.getValue(),new_parameter.getType())

            modified_request.append(first_req)

            #self._stdout.println(requestString)
        return modified_request


    def	registerExtenderCallbacks(self, callbacks):
        # keeping a reference to our callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("BurpBugFinder")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
       
        
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)
        self._stdout.println("Extension is Loaded")

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        

    #
    # implement ITab
    #
    
    def getTabCaption(self):
        
        return "BurpBugFinder"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IProxyListener
    #
   

    def processProxyMessage(self, messageIsRequest, message):
        self._stdout.println(
                        ("Proxy request to " if messageIsRequest else "Proxy response from ") +
                        message.getMessageInfo().getHttpService().toString())

        messageInfo=message.getMessageInfo()
        
        if messageIsRequest:
            requestString = messageInfo.getRequest().tostring()    
            self._stdout.println("Processing")
        
            reqs=self.processit(requestString,messageInfo)
            for req in reqs:
                func = self._callbacks.makeHttpRequest
                thread = Thread(target=func, args=(messageInfo.getHttpService(), req))
                thread.start()     

 
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        msgResponse  = self._helpers.bytesToString(messageInfo.getResponse()[responseInfo.getBodyOffset():])
        

        if(XSS_payload in msgResponse):
            #print(messageInfo.getResponse()[responseInfo.getBodyOffset():])
            self._lock.acquire()
            row = self._log.size()
            #self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
            self._log.add(LogEntry("XSS "+XSS_payload, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
            self.fireTableRowsInserted(row, row)
            self._lock.release()
            issue = CustomIssue(
                        BasePair=messageInfo,
                        IssueName='XSS [BurpBugFinder]',
                        IssueDetail="Payload sent : "+XSS_payload,
                        Severity='High',
                    )
            self._callbacks.addScanIssue(issue)

        if(SQLi_message_trigger.lower() in msgResponse.lower()):
            #print(messageInfo.getResponse()[responseInfo.getBodyOffset():])
            self._lock.acquire()
            row = self._log.size()
            #self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
            self._log.add(LogEntry("Error based SQLi", self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
            self.fireTableRowsInserted(row, row)
            self._lock.release()
            issue = CustomIssue(
                        BasePair=messageInfo,
                        IssueName='Possible SQLi [BurpBugFinder]',
                        IssueDetail="An error based SQLi has been found in this request",
                        Severity='High',
                    )
            self._callbacks.addScanIssue(issue)

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Possible vulnerability"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            #return self._callbacks.getToolName(logEntry._tool)
            return logEntry._tool
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
 

   
from burp import IScanIssue


class CustomIssue(IScanIssue):

    def __init__(self, BasePair, Confidence='Certain', IssueBackground=None, IssueDetail=None, IssueName='BurpBugFinder generated issue', RemediationBackground=None, RemediationDetail=None, Severity='High'):

        self.HttpMessages=[BasePair] # list of HTTP Messages
        self.HttpService=BasePair.getHttpService() # HTTP Service
        self.Url=BasePair.getUrl() # Java URL
        self.Confidence = Confidence # "Certain", "Firm" or "Tentative"
        self.IssueBackground = IssueBackground # String or None
        self.IssueDetail = IssueDetail # String or None
        self.IssueName = IssueName # String
        self.IssueType = 134217728 # always "extension generated"
        self.RemediationBackground = RemediationBackground # String or None
        self.RemediationDetail = RemediationDetail # String or None
        self.Severity = Severity # "High", "Medium", "Low", "Information" or "False positive"

    def getHttpMessages(self):

        return self.HttpMessages

    def getHttpService(self):

        return self.HttpService

    def getUrl(self):

        return self.Url

    def getConfidence(self):

        return self.Confidence

    def getIssueBackground(self):

        return self.IssueBackground

    def getIssueDetail(self):

        return self.IssueDetail

    def getIssueName(self):

        return self.IssueName

    def getIssueType(self):

        return self.IssueType

    def getRemediationBackground(self):

        return self.RemediationBackground

    def getRemediationDetail(self):

        return self.RemediationDetail

    def getSeverity(self):

        return self.Severity
