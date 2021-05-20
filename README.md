## **NAPALM INTEGRATION WITH NOKIA SR LINUX**

#### **NAPALM**
NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

#### **SRL OS**
NAPALM integration is validated with a minimum of Nokia Service Router Linux Operating System (SRL OS) version 21.3.1. Releases beyond this have not been validated and should be by users before using the driver in labs and production on devices using different SRL OS versions. Please contact the Nokia owners of this repository for additional information with respect to additional release validation.


#### **Documentation**
1) Please read the installation instruction in [Install Document](Install.md)
2) napalm_srl/srl.py: Overridden NAPALM methods to get the expected output from SRL OS
4) Mapping of various parameters of NAPALM output to Nokia SRL can be found in this [Mapping Document](Summary_of_Methods.pdf)
6) For testing, please refer to [Test Document](https://napalm.readthedocs.io/en/latest/development/testing_framework.html)

#### **Components **
1) Python - 3.6
2) grpcio
3) protobuf

##### **Note**
The SRL Network Drivers uses gNMI for Get Functions and JSON RPC for Load/SET Functions
User prior should generate valid certificates along with  Signing CA in order to successfully use SRL Node with NAPALM.
This version of the driver leverages Nokia’s defined SRL YANG models for configuration and state trees for the SRL platform.
Load_Replace function has been developed using gNMI SET REPLACE option which has implicit commit.

#### License
This project is licensed under the Apache-2.0 license - see the [LICENSE](LICENSE) file. 
