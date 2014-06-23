# Kraken - a Host-based IOC collection framework

![The Kraken's panel](/kraken-panel.png)

The Kraken is a host-based IOC collection framework, crucial in the identification phase of any incident response.

The Kraken is built around two main components:

* Lightweight agent that is installed on each individual system
* A central repository (or C2 server) where evidence is collected and invidual commands can be issued to the agents

The Kraken is in a very early alpha state. Lots of features have been developed in a "quick and dirty" fashion, but are easy to implement in pure python when time permits.

## Features
After being deployed and launched, the Kraken will reach out to its C2 server and update its configuration (yes, we learned from the best :)). The configuration file will contain a set of artifacts to look for, as well as any eventual commands that the host should execute.

The Kraken will look for the following artifacts:
* MD5 hashes
* SHA-256 hashes
* Filesystem regular expressions in paths or filenames

Commands include:
* Retreive an arbitrary file from the system (plaintext or encrypted)
* Search for registry keys in the system
* Retreive the content of an arbitrary registry key
* Dump the system's memory to the C2 server over TCP

So as no to traverse the disk every time the Kraken searches for an artifact, the Kraken will periodically generate a list of hashes of all files in the filesystem. The searches will be made on that file only at specific intervals. In that way, a list of artifacts can be set up and the Kraken will be notified as soon as it is found on one of the subscribed computers.

## Installation
The repository contains two directories of interest, `kraken-agent` and `kraken-panel`. Installation is pretty straightforward.

### Setup
The Kraken agents need to be able to issue HTTP requests to the Kraken C2 server (unauthenticated proxy servers are an option).

### Kraken agent
The Kraken agent is meant to be self-contained and does not require any installation. You can just copy the folder on the target computer's disk, unzip the contents of App.zip (the standalone-python interpeter) and you're good to go.

### Kraken panel
The Kraken's web interface and control server are a Django application based. The use of a python virtual environment is recommended.

1. Clone the panel directory onto any Ubuntu 14.04 server instance
2. Install dependencies: `django-panel$ pip install django django-suit`
3. Run the Django webserver: `django-panel$ python manage.py runserver 0.0.0.0:80`
4. Hunt!


## Roadmap
The Kraken has a long roadmap ahead of it. You are all encouraged to contribute. The project is at such an early stage that small contributions entail great progress. 

Some ideas:

* Integrate functions that are called via external executables (e.g. hashdeep) and which are easily implementable in python
* Deal with authenticated proxies to communicate with the C2 server
* Bundle the executable using pyinstaller or py2exe (to ease deployment)
* Add some encryption
* OpenIOC itegration
* Live memory forensics (probably using rekall)









