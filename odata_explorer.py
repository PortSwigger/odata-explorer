from burp import IBurpExtender, ITab, IExtensionStateListener
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JSplitPane, BoxLayout
from java.awt import BorderLayout, Dimension
import javax.swing.JOptionPane as JOptionPane
import xml.dom.minidom as minidom
import json
from java.awt.event import ActionListener


class ButtonClickListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        metadata_text = self.extender.metadata_area.getText()
        data = self.extender.format_data(self.extender.generate_requests(metadata_text))
        formatted_data = ""
        for element in data:
            formatted_data += str(element) + "\n"
        
        self.extender.result_area.setText(formatted_data)    
        #self.extender.result_area.setText(data)

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("OData Explorer")
        self.init_gui()
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)

    def extensionUnloaded(self):
        # No resources to release in this specific extension
        pass

    def init_gui(self):
        self.main_panel = JPanel(BorderLayout())

        self.generate_button = JButton("Generate Requests")
        button_click_listener = ButtonClickListener(self)
        self.generate_button.addActionListener(button_click_listener)
        self.main_panel.add(self.generate_button, BorderLayout.NORTH)

        self.content_panel = JPanel()
        self.content_panel.setLayout(BoxLayout(self.content_panel, BoxLayout.X_AXIS))
        self.main_panel.add(self.content_panel, BorderLayout.CENTER)

        self.metadata_area = JTextArea("Insert metadata XML here!")
        self.metadata_area.setWrapStyleWord(True)
        self.metadata_scroll = JScrollPane(self.metadata_area)
        self.metadata_scroll.setPreferredSize(Dimension(400, 200))
        self.content_panel.add(self.metadata_scroll)

        self.result_area = JTextArea()
        self.result_area.setWrapStyleWord(True)
        self.result_area.setEditable(True)
        self.result_scroll = JScrollPane(self.result_area)
        self.result_scroll.setPreferredSize(Dimension(400, 200))
        self.content_panel.add(self.result_scroll)

    def generate_requests(self, metadata_xml):
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
            entity_type_name = entity_set.getAttribute("EntityType")
            entity_type = dom.getElementsByTagNameNS(namespaces['edm'], 'EntityType')
            properties = []

            for et in entity_type:
                if et.getAttribute("Name") == entity_type_name.split('.')[-1]:
                    properties = et.getElementsByTagNameNS(namespaces['edm'], 'Property')

            parameters = []
            for prop in properties:
                prop_name = prop.getAttribute("Name")
                prop_type = prop.getAttribute("Type")
                if prop_type.startswith("Edm.String"):
                    parameters.append("{} eq '{{{}}}'".format(prop_name, prop_name))
                else:
                    parameters.append("{} eq {{{}}}".format(prop_name, prop_name))

            filter_string = " and ".join(parameters)
            url = "{}/{}/?$filter={}".format(service_url, name, filter_string)
            http_requests.append({"method": "GET", "url": url, "parameters": {}})

        # Add requests for actions (POST method)
        for action in actions:
            name = action.getAttribute("Name")
            url = "{}/{}".format(service_url, name)
            parameters = {}
            for param in action.getElementsByTagNameNS(namespaces['edm'], 'Parameter'):
                param_name = param.getAttribute("Name")
                param_type = param.getAttribute("Type")
                parameters[param_name] = {"type": param_type, "value": None}  
            http_requests.append({"method": "POST", "url": url, "parameters": parameters})
        
        # Add requests for functions (GET method)
        for function in functions:
            name = function.getAttribute("Name")
            url = "{}/{}".format(service_url, name)
            parameters = {}
            for param in function.getElementsByTagNameNS(namespaces['edm'], 'Parameter'):
                param_name = param.getAttribute("Name")
                param_type = param.getAttribute("Type")
                parameters[param_name] = {"type": param_type, "value": None}
                if param == function.getElementsByTagNameNS(namespaces['edm'], 'Parameter')[0]:
                    url += "("
                else:
                    url += ","
                url += "{}={}".format(param_name, "{{{}}}".format(param_name))
            url += ")"
            http_requests.append({"method": "GET", "url": url, "parameters": parameters})
        
        return http_requests

    

    def format_data(self, data):
        requests = []
        for row in data:
            method = row["method"]
            url = row["url"]
            parameters = row["parameters"]

            if method == 'GET':
                params = "&".join(["{}={}".format(key, value["value"]) for key, value in parameters.items() if value["value"] is not None])
                if params:
                    url += "?" + params
                request = "{} {} HTTP/1.1\r\nHost: your-odata-service-url\r\n\r\n".format(method, url)

            elif method == 'POST':
                payload = {}
                for key, value in parameters.items():
                    if value["value"] is None:
                        if value["type"] == u'Edm.String':
                            payload[key] = ''
                        else:
                            continue
                    else:
                        payload[key] = value["value"]

                payload_json = json.dumps(payload)
                headers = "Content-Type: application/json\r\nContent-Length: " + str(len(payload_json)) + "\r\n"
                request = method + " " + url + " HTTP/1.1\r\nHost: your-odata-service-url\r\n" + headers + "\r\n" + payload_json + "\r\n"
            else:
                raise NotImplementedError("Unsupported method: {}".format(method))

            requests.append(request)

        return requests


    def getTabCaption(self):
        return "OData Extractor"

    def getUiComponent(self):
        return self.main_panel