# Double Ratchet implementation in Python3

Python3 implementation of the Double Ratchet Algorithm by Signal app. It does not include key agreement protocol (such as X3DH) to agree on the shared secret key, header encryption nor out-of-order messages. To deliver messages between both ends, MQTT protocol is used, so a MQTT server is needed.

## Installation

```sh
pip3 install -r requirements.txt
``` 

## Usage

First:

```sh
python3 double_ratchet.py in
``` 

**After that**, on other instance:

```sh
python3 double_ratchet.py out
``` 

## How it works

Bob (OUT) starts sending the DH parameters to Alice (IN). Then, Alice (IN) automatically sends a message to Bob (OUT) to start the conversation. After that, the system is initialized, and both console inputs are enabled to start chatting.

## References
[1] The Double Ratchet Algorithm: https://signal.org/docs/specifications/doubleratchet/
