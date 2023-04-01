import xml.dom.minidom as minidom
import json


with open('metadata02.xml', 'r') as file:
    metadata_xml = file.read()


def generate_requests(metadata_xml):
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

def format_data(data):
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


data = format_data(generate_requests(metadata_xml))

for element in data:
    print(element)