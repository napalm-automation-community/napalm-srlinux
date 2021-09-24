## Installation Steps
**Note**: Certificates are needed to establish successful connection with node. [Refer here for TLS Profiles at SR Linux](https://infocenter.nokia.com/public/SRLINUX200R6A/index.jsp?topic=%2Fcom.srlinux.configbasics%2Fhtml%2Fconfigb-config-mgmt.html)

**Installation**

1. **Configurations at SR Linux Node**

	- Create a TLS Server Profile
        ```
        --{ running }--[ system tls ]--
            A:srl# info
                server-profile tls-profile-1 {
                    key "server_side key copy here"
                    certificate "server_side_certificate copy here"
                    authenticate-client true
                    trust-anchor "Signing CA copy here"
                }
        ```
    - Create gNMI Server Configurations
        ```
        --{ running }--[ system gnmi-server ]--
        A:srl# info
        admin-state enable
        timeout 7200
        rate-limit 60
        session-limit 20
        network-instance mgmt {
            admin-state enable
            use-authentication true
            port 57400
            tls-profile tls-profile-1
        }
        ```
        
    - Create JSON RPC Server Configurations
        ```
        --{ running }--[ system json-rpc-server ]--
        A:srl# info
        admin-state enable
        network-instance mgmt {
            http {
                admin-state enable
                use-authentication true
                session-limit 1
                port 80
            }
            https {
                admin-state enable
                use-authentication true
                session-limit 1
                port 443
                tls-profile tls-profile-1
                source-address [
                    ::
                ]
            }
        }
       ```   

2. **Configurations at NAPALM computer where the napalm-srlinux driver will be running**

	- Clone the napalm-srlinux repository on your local computer.
        ```
        git clone https://github.com/napalm-automation-community/napalm-srlinux.git
        ```
   	- Install the required packages
    ```pip install -r requirements.txt```
    <br/>
	- Install the drivers using the command, (Make sure Python3 is running) 
    ```python setup.py install``` 

	
**Verification**

Run the example script by pointing to correct certificates.

```
# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

from napalm import get_network_driver
import json

driver = get_network_driver("srl")
optional_args = {
    "gnmi_port": 57400,
    "jsonrpc_port": 80,
    "target_name": "172.20.20.2",
    "tls_cert":"/root/gnmic_certs/srl_certs/clientCert.crt",
    "tls_ca": "/root/gnmic_certs/srl_certs/RootCA.crt",
    "tls_key": "/root/gnmic_certs/srl_certs/clientKey.pem",
     #"skip_verify": True,
     #"insecure": False
    "encoding": "JSON_IETF"
} 
device = driver("172.20.20.2", "admin", "admin", 60, optional_args)
device.open()

print(json.dumps(device.get_facts())) 

device.close()
```
We welcome suggestions and contributions. Please contact the Nokia owners of this repository for how to contribute.

