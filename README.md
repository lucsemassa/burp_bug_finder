# burp_bug_finder

Burp_bug_finder is a custom burpuite plugin (written in python) that makes easy the discovery of web vulnerabilities. 
This first version focuses only on XSS, **there's no need to manually send xss payload either for reflected or stored payload**; you just need to browse to the pages where you want to check the XSS vulnerability.

# How to install
1. Install jython and include it in the extender tab. 
The lastest version (2.7.3) at today date can be downloaded here https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar

2. Include the jython in the python environment in Extender > Options > Python Environment 
![Jython installation](images/jython.png)

3. Download the burp_bug_finder.py from this repository and include it the the extension.


# How it works 

burp_bug_finder captures all requests sent through the proxy and resend them by modifiying every parameter (including cookie) with an XSS payload.
The payload is then checked in the response of the request.

If the payload pattern is found in the response, a log is added in the tab named BurpBugFinder.
![Payload sent](images/payload_sent.png)

**NB:** Since every request sent is tweaked, kindly enable the extension only when you want to check for bug.

# References
- https://portswigger.net/burp/extender#SampleExtensions
- https://gist.github.com/irsdl/0ab8fce5368e449df64ed89c1b7323a6
- https://cirius.medium.com/writing-your-own-burpsuite-extensions-complete-guide-cb7aba4dbceb
