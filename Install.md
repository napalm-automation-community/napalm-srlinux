## Installation Steps

1) Configurations at SR Linux Node involves 3 steps, Follow the below steps:
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

2) From [NAPALM NOKIA REPO](https://github.com/napalm-automation-community/napalm-sros) clone the repository on your local computer
    ```
   git clone https://github.com/napalm-automation-community/napalm-sros
   ``` 
   
3) Install requirements using command `pip install -r requirements.txt` 
4) Run a script to get the results.
   ##### Usage Example
    ```
    from napalm import get_network_driver
    import json

    driver = get_network_driver("srl")
    optional_args = {
        "port": 57400,
        "target_name": "172.20.20.2",
        "tls_ca":"/root/gnmic_certs/srl_certs/clientCert.crt",
        "tls_cert": "/root/gnmic_certs/srl_certs/RootCA.crt",
        "tls_key": "/root/gnmic_certs/srl_certs/clientKey.pem",
        "skip_verify": True,
        "insecure": True,
        "encoding": "JSON_IETF"
    }
    device = driver("172.20.20.2", "admin", "admin", 60, optional_args)
    device.open()

    print(json.dumps(device.get_bgp_neighbors()))

    device.close()
   ```
 

We welcome suggestions and contributions. Please contact the Nokia owners of this repository for how to contribute.

