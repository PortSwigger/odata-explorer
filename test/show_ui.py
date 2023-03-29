from burp import IBurpExtender
from java.io import PrintWriter
import xml.dom.minidom as minidom

class BurpExtender(IBurpExtender):

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)

        message = self.generate_requests()
        self.stdout.println(message)

        return

    def generate_requests(self):
        metadata_xml = '''<?xml version="1.0" encoding="utf-8"?>
        <edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx">
            <edmx:DataServices xml:base="https://your-odata-service-url"
                xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                <Schema Namespace="Example" xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
                    <EntityType Name="Product">
                        <Key>
                            <PropertyRef Name="ID" />
                        </Key>
                        <Property Name="ID" Type="Edm.Int32" Nullable="false" />
                        <Property Name="Name" Type="Edm.String" Nullable="false" />
                        <Property Name="Price" Type="Edm.Decimal" Nullable="false" />
                    </EntityType>
                    <EntityType Name="Category">
                        <Key>
                            <PropertyRef Name="ID" />
                        </Key>
                        <Property Name="ID" Type="Edm.Int32" Nullable="false" />
                        <Property Name="Name" Type="Edm.String" Nullable="false" />
                    </EntityType>
                    <EntityContainer Name="ExampleEntities" m:IsDefaultEntityContainer="true">
                        <EntitySet Name="Products" EntityType="Example.Product" />
                        <EntitySet Name="Categories" EntityType="Example.Category" />
                    </EntityContainer>
                    <Action Name="AddProduct">
                        <Parameter Name="Name" Type="Edm.String" />
                        <Parameter Name="Price" Type="Edm.Decimal" />
                        <ReturnType Type="Example.Product" />
                    </Action>
                    <Function Name="GetProductsByCategory" ReturnType="Collection(Example.Product)">
                        <Parameter Name="CategoryID" Type="Edm.Int32" />
                    </Function>
                </Schema>
            </edmx:DataServices>
        </edmx:Edmx>
        '''

        # Parse the XML
        dom = minidom.parseString(metadata_xml)

        # XML namespaces
        namespaces = {
            "edmx": "http://schemas.microsoft.com/ado/2007/06/edmx",
            "edm": "http://schemas.microsoft.com/ado/2008/09/edm",
        }

        # Find the base URL for the OData service
        service_url = dom.getElementsByTagNameNS(namespaces['edmx'], 'DataServices')[0].getAttribute("xml:base")

        # Find all entity sets, actions, and functions
        entity_sets = dom.getElementsByTagNameNS(namespaces['edm'], 'EntitySet')
        actions = dom.getElementsByTagNameNS(namespaces['edm'], 'Action')
        functions = dom.getElementsByTagNameNS(namespaces['edm'], 'Function')

        # Generate the HTTP requests
        http_requests = []

        # Add requests for entity sets (GET method)
        for entity_set in entity_sets:
            name = entity_set.getAttribute("Name")
            url = "{}/{}".format(service_url, name)
            http_requests.append({"method": "GET", "url": url, "parameters": {}})

        # Add requests for actions (POST method)
        for action in actions:
            name = action.getAttribute("Name")
            url = "{}/{}".format(service_url, name)
            parameters = {}
            for param in action.getElementsByTagNameNS(namespaces['edm'], 'Parameter'):
                param_name = param.getAttribute("Name")
                param_type = param.getAttribute("Type")
                parameters[param_name] = {"type": param_type, "value": None}  # Replace None with the appropriate value
            http_requests.append({"method": "POST", "url": url, "parameters": parameters})

        # Add requests for functions (GET method)
        for function in functions:
            name = function.getAttribute("Name")
            url = "{}/{}".format(service_url, name)
            parameters = {}
            for param in function.getElementsByTagNameNS(namespaces['edm'], 'Parameter'):
                param_name = param.getAttribute("Name")
                param_type = param.getAttribute("Type")
                parameters[param_name] = {"type": param_type, "value": None}  # Replace None with the appropriate value
                url += "({}={{{}}})".format(param_name, param_name)  # Add the parameter to the URL
            http_requests.append({"method": "GET", "url": url, "parameters": parameters})

        
        #for row in http_requests:
            #result_text += "\t".join(row) + "\n"

        return http_requests





