# ComputerSecurityMC-MitM

## Prerequisites

- Python 3.3 or later

## Step 1: Install the venv module

The `venv` module is included in Python 3.3 and later versions. If you're using an earlier version of Python, you'll need to install the `virtualenv` package.

## Step 2: Create a virtual environment

Decide upon a directory where you want to place your virtual environment, and run the `venv` module as a script with the directory path:

 python3 -m venv venv

This will create the `venv` directory if it doesn't exist, and also create directories inside it containing a copy of the Python interpreter and various supporting files.

## Step 3: Activate the virtual environment

Activating the virtual environment will change your shell’s prompt to show what virtual environment you’re using, and modify the environment so that running `python` will get you that particular version and installation of Python.

On Windows:

.\venv\Scripts\activate


On Unix or MacOS:

source venv/bin/activate


## Step 4: Install packages

Now that your virtual environment is activated, you can install packages using `pip`. These packages will only be installed in the virtual environment, not system-wide.

## Step 5: Installation

To install the necessary dependencies, run the following command in the wifi-sniffer directory:


pip install -r requirements.txt

## Step 6: Running

To run the project use the following python command in the wifi-sniffer directory:

python pcapgui.py 
