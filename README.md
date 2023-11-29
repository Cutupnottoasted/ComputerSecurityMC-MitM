<a name="readme-top"></a>



# ComputerSecurityMC-MitM - Wifi-Sniffer

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
        <li><a href="#supported-protocols--standards">Supported Protocols & Standards</a>
      </ul>
    </li>
    <li>
      <a href="#setup">Setup</a>
      <ul>
        <li><a href="#step-1-install-the-venv-module">Step 1: Install Venv Module</a></li>
        <li><a href="#step-2-create-a-virtual-environment">Step 2: Create a Virtual Enviorment</a></li>
        <li><a href="#step-3-activate-the-virtual-environment">Step 3: Activate the Virtual Enviorment</a></li>
        <li><a href="#step-4-install-packages">Step 4: Install Packages</a></li>
        <li><a href="#step-5-installation">Step 5: Installation</a></li>
        <li><a href="#step-6-running">Step 6: Running</a></li>
      </ul>
    </li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

# About The Project
This program is used to detect suspicious activity by analyzing pcap files. It is able to detect rapid probe requests and duplicate nonce values that occur during 4-Way-Handshakes.

## Built With

- Python 3.3 or later

## Supported Protocols & Standards 
 - WiFi Protected Setup (WPS)
 - Extensible Authenticaiton Protocol over Lan (EAPOL)
 - Wi-Fi Protected Access 2 (WPA2)
 - IEEE 802.11 (802.11)
 
# Setup

## Step 1: Install Venv Module

The `venv` module is included in Python 3.3 and later versions. 

*If you're using an earlier version of Python, you'll need to install the `virtualenv` package.

## Step 2: Create a Virtual Environment

Decide upon a directory where you want to place your virtual environment, and run the `venv` module as a script with the directory path:
```
python3 -m venv venv
```
This will create the `venv` directory if it doesn't exist, and also create directories inside it containing a copy of the Python interpreter and various supporting files.

## Step 3: Activate the Virtual Environment

Activating the virtual environment will change your shell’s prompt to show what virtual environment you’re using, and modify the environment so that running `python` will get you that particular version and installation of Python.

On Windows:
```
.\venv\Scripts\activate
```

On Unix or MacOS:
```
source venv/bin/activate
```

## Step 4: Install Packages

Now that your virtual environment is activated, you can install packages using `pip`. These packages will only be installed in the virtual environment, not system-wide.

## Step 5: Installation

To install the necessary dependencies, run the following command in the wifi-sniffer directory:
```
pip install -r requirements.txt
```
## Step 6: Running

To run the project use the following python command in the wifi-sniffer directory:
```
python pcapgui.py 
```
## Contact

- [Zach Boston](https://www.linkedin.com/in/zach-b-6a0839236/) - wyb5@txstate.edu
- [Mateo Paul Cordeiro]() - mpc89@txstate.edu
- [Cody Nguyen Hoang](https://www.linkedin.com/in/cody-hoang-b9a741256/) - cnh71@txstate.edu
- [David Mocjica](https://www.linkedin.com/in/david-mojica-9b6090188/) - fdf16@txstate.edu
- [Tomoray Scott](https://www.linkedin.com/in/tomoray-scott-560227121/) - tms@txsate.edu

* Project Link: https://github.com/Cutupnottoasted/ComputerSecurityMC-MitM/tree/main

## Acknowledgments
* [Multi-Channel Man-in-the-Middle](https://www.sciencedirect.com/science/article/pii/S0957417422015093#ak005)
* [krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)
* [krackdetector](https://github.com/securingsam/krackdetector)
* [wig-ng](https://github.com/6e726d/wig-ng)