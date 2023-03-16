## Installation Steps
**Note**: Certificates are needed to establish a successful connection with node. [Refer here for TLS Profiles at SR Linux](https://infocenter.nokia.com/public/SRLINUX200R6A/index.jsp?topic=%2Fcom.srlinux.configbasics%2Fhtml%2Fconfigb-config-mgmt.html)

During development and for quick testing, the ```insecure``` driver parameter can be set to bypass the need for certificates. Obviously, this is not recommended for production deployments

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

1.a (optional) **Dedicated user account for NAPALM driver access**

To configure a dedicated user account for NAPALM driver access:
```
A:srl# info
    configuration {
        role napalm {
            rule / {
                action write
            }
        }
    }
    aaa {
        authentication {
            user napalm {
                password "<some secure password>"
                role [
                    napalm
                ]
            }
        }
        authorization {
            role napalm {
                services [
                    gnmi
                    json-rpc
                ]
            }
        }
    }
```

If desired, access to the configuration can be further restricted. For example, to prevent NAPALM from overwriting aaa access rules to the system:
```
A:srl# info
    configuration {
        role napalm {
            rule / {
                action write
            }
            rule "/system aaa" {
                action read
            }
        }
    }
```

2. **Configurations where the napalm-srlinux driver will be installed/running**

	- Clone the napalm-srlinux repository</br>
	    ```
	    git clone https://github.com/napalm-automation-community/napalm-srlinux.git
	    ```
	- Install the required packages</br>
	    ```
	    pip install -r requirements.txt
	    ```
	- Install the driver</br>
	    ```
	    python3 setup.py install
	    ```


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
