# burp_bug_finder

Burp_bug_finder is a custom burpuite plugin (written in python) that makes easy the discover of web vulnerability. 
This first version focus only on XSS, **there's no need to manually send xss payload either for reflected or stored payload**; you just need to browse to the pages where you want to check the XSS vulnerability.

# How to install
1. Install jython and include it in the extender tab. [Image]
The lastest version (2.7.3) at today date can be downloaded here https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar

2. Download the burp_bug_finder.py from this repository and include it the the extension.


# How it works 

burp_bug_finder capture all requests sent through the proxy and resend it by modifiying every parameters (including cookies) with an XSS payload.
The payload is then checked in the request response.

If the payload pattern is found in the request response, the log is added in the tab named BurpBugFinder.
[Image]

**NB:** Since every request sent is tweaked, kindly enable the extension only when you want to check for bug.