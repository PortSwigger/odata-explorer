# OData Explorer

OData Explorer is a Burp Suite extension specifically designed for black-box security testing of OData services. Leveraging Service Metadata Documents, this tool automates the creation of attack templates and helps security professionals efficiently identify potential vulnerabilities in their OData implementations.

![alt text](./img/odata_explorer.png "OData Explorer")

# Installation

1. Download Burp Suite: http://portswigger.net/burp/download.html
2. Download Jython standalone JAR: http://www.jython.org/download.html
3. Open burp -> Extender -> Options -> Python Environment -> Select File -> Choose the Jython standalone JAR
4. Import odata_explorer.py into Bapp list

# Usage

OData Explorer possesses the capability to generate HTTP requests based on Service Metadata Documents. Utilizing this feature is incredibly straightforward. Simply copy the corresponding XML metadata document, then click the "Generate Requests" button. This will produce a list of valid HTTP requests, complete with appropriate URIs, query paramete and request bodies.
