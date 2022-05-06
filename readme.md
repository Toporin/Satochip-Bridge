# Satochip-Bridge

This python tool acts as a midleware between a wallet client and a Satochip connected to a card reader. 
This tool allows to facilitate communication between various wallet by abstracting the protocol layer and communication with a card reader.
It also allows a javascript to connect to a Satochip from the browser as in the case of web client.

## Requirements

Python dependencies can be installed with:
    
    $ python3 -m pip install -r contrib/requirements/requirements.txt
    

## Run from sources
    
    $ python3 satochip_bridge/SatochipBridge.py
    

## Build the Linux binaries

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system. The host architecture should be x86_64 (amd64).
The docker commands should be executed in the project's root folder.

The script is based on [Electrum building script](https://github.com/spesmilo/electrum/tree/master/contrib/build-linux/appimage)

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build docker image
    ```
	$ sudo docker build -t satochip-bridge-appimage-builder-img contrib/build-linux/appimage
    ```
	
3. Build AppImage
    ```
	$ sudo docker run -it \
		--name satochip-bridge-appimage-builder-cont \
		-v $PWD:/opt/satochip_bridge \
		--rm \
		--workdir /opt/satochip_bridge/contrib/build-linux/appimage \
		satochip-bridge-appimage-builder-img \
		./build.sh
    ```

4. The generated binary is in `./dist`.
