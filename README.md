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

As always, the use of a virtual environment is recommended:

1. Install pywin32
2. Install your virtual environment: `python virtualenv.py --system-site-packages env-kraken`
3. Activate it
4. `pip install -r requirements-agent.txt`
5. `pip install -r requirements-agent.txt`

### Setup
The Kraken agents need to be able to issue HTTP requests to the Kraken C2 server (unauthenticated proxy servers are an option).

### Kraken agent
The Kraken agent is meant to be self-contained and does not require any installation. You can run it using a local python interpreter or using `pyinstaller`

* Make sure you installed `pywin32` and that `pyinstaller` is in your path (it should be if you installed it via `pip`).
* From the `kraken-agent/agent/bin` folder run `pyinstaller -F kraken.py`
* It will create a standalone PE in the `dist` subdirectory

### Kraken panel
The Kraken's web interface and control server are a Django application based. The use of a python virtual environment is recommended.

1. Clone the panel directory onto any Ubuntu 14.04 server instance
2. Initialize the database: `$ python manage.py syncdb`. It will prompt you for admin credentials.
3. Run the Django webserver: `$ python manage.py runserver 0.0.0.0:80`
4. Login to `http://localhost:80/`, enter the credentials you specified in step 2.
5. Hunt!

## Roadmap
The Kraken has a long roadmap ahead of it. You are all encouraged to contribute. The project is at such an early stage that small contributions entail great progress.

Some ideas:

* Integrate functions that are called via external executables (e.g. hashdeep) and which are easily implementable in python
* Deal with authenticated proxies to communicate with the C2 server
* Bundle the executable using pyinstaller or py2exe (to ease deployment)
* Add some encryption
* OpenIOC itegration
* Live memory forensics (probably using rekall)

## License

Kraken Copyright (C) 2014 Société Générale

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.

## Thanks

Thanks to the Quarkslab team for pointing out some security issues with the server. They've been fixed.
