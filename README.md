# AESCrypto Elliptic Curve Dilfie-Hellman key agreement test

This code tests the communication of encrypted data from an ESP8266/ESP32 to a NodeJS server that receives AES128 CBC PKCS#7 encrypted message and decrypts it onboard.
There key used for the AES128 encryption and decryption is negociated by using the DH key agreement protocol and using ellipti curves cryptography spceifically the Curve25519.

This is a follow-up on the [comment section of my blog post regarding ESP8266/NodeJs and encryption](https://primalcortex.wordpress.com/2016/06/17/esp8266-logging-data-in-a-backend-aes-and-crypto-js/).

The original post discusses encrypting data on the device and send it to a NodeJs server.

Thei original code in this [repository](https://github.com/fcgdam/AESCrypto_Test), implements a test program that show cases sending and receiving data from and to the ESP8266 and NodeJS using AES128 encryption but using a pre-shared key.

This repository, as discussed in this Wordpress post: [Establishing secure ESP8266 and NodeJs communication by using Diffie-Hellman key exchange and Elliptic Curves](https://primalcortex.wordpress.com/?p=2086&preview=true) has the test program that enables the use of ephemeral negociated symmetric keys between the ESP and the NodeJS server, so no predefined key is necessary to be configured.

# Flashing the firmware on the ESP8266.

Install PlatformIO, and just run *pio run -t upload* to flash the board.

But before doing that three things need to be changed: the SSID and Password of the WIFI access point must be modified and the IP address of the target NodeJs Server. Change it at the top of the *src/main.cpp* file.

After connection, take note of the IP.

# Testing ESP8266 to NodeJS

On the *Node_Server* folder there is the server component that waits for data sent from the ESP8266, decrypts it and shows it on the console.
The default listening port is 8087.

To run the code just run *npm install* once, and then the code can be run with *node server.js*. The server should start to listen for incoming data.
Note that the IP of the server must be previously defined on the ESP8266 software.


# Final notes:

This code only shows that it is possible to implement ECDH Curve25519 based key agreement so only works from one device ESP8266 to the server.
For supporting multiple devices a session mechanism must be implemented, and when the ESP8266 sends data also sends a session identifier to let the server know which negociated key should use to decrypt the incoming data.
