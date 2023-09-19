## **Nokia napalm-srlinux**
Community NAPALM driver for the Nokia SR Linux OS. [https://www.nokia.com/networks/products/service-router-linux-NOS/](https://www.nokia.com/networks/products/service-router-linux-NOS/) 

# Getting started - quick connection code snippet
```
driver = get_network_driver("srl")
optional_args = {
  "gnmi_port": 57400, # default
  "jsonrpc_port": 443, # default

  # "tls_ca": tls_ca, # Root CA to verify SSL connections
  # "tls_cert": cwd + "srl/client.pem",
  # "tls_key": cwd + "srl/client.key",
  # "skip_verify": True,
  "insecure": True, # FOR TESTING PURPOSES ONLY - this uses the server certificate as root of trust
  "encoding": "JSON_IETF"
}
device = driver("host-or-ip", "admin", "NokiaSrl1!", 10, optional_args)
device.open()
facts = device.get_facts()
print( facts )
device.close()
```

#### **NAPALM**
NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

#### **SR Linux OS**

The driver leverages Nokia SRL YANG models for configuration and state trees for the SRL platform.
NAPALM integration is validated with a minimum of Nokia Service Router Linux Operating System (SRL OS) version 21.3.1. 

Releases beyond this have not been validated and should be by users before using the driver in labs and production on devices using different SRL OS versions. Please contact the Nokia owners of this repository for additional information with respect to additional release validation.


#### **Documentation**
1) Please read the installation instruction in [Install Document](Install.md)
2) Mapping of various parameters of NAPALM output to Nokia SRL can be found in this [Mapping Document](Summary_of_Methods.pdf)
3) For testing, please refer to [Test Document](https://napalm.readthedocs.io/en/latest/development/testing_framework.html)

#### **Components **
1) Python (3.7 or later)
2) grpcio
3) protobuf

##### **Important Notes**

1. **Ports**: The napalm-srlinux driver uses gNMI and JSON-RPC for various functions, Make sure to enable the ports at SR Linux Node (57400 and 443 respectively by default)
2. **Certificates**: The napalm-srlinux driver establishes secure connection only with the node, Hence make sure the appropriate CA/Certificates and Keys are in place.
   For testing purposes, 'insecure=True' can be used to accept any certificate presented by the device
3. **Compare_Config**: The `compare_commit` based on the previously called function performs the operation as below, Default is on-box difference

	| Function | compare_config |
	|----------|----------------|
	|LOAD_MERGE| on-box difference|
	|LOAD_REPLACE|out-box difference

4. **Proxy Setting**: The driver establishes RPC connections with the nodes, Check proxy settings at local machine(where driver is running), Disable proxy if not needed when running locally.


#### License
This project is licensed under the Apache-2.0 license - see the [LICENSE](LICENSE) file. 

