# WaveSentry
Custom firmware for the WaveSentry Portable ESP32 Multi-Tool

The WaveSentry is a portable Multifuction ESP32 testing tool created for Audio Receiver, Thermal Imaging Camera, WiFi and Bluetooth Analysis. 

# Introduction
The WaveSentry and WaveSentry Pro are portable Multifuction ESP32 testing tools. They are based on the ESP32 Marauder and has undergone a hardware redesign.
WaveSentry includes the functions of Radio Receiver, WiFi and Bluetooth Analysis.
WaveSentry Pro includes the functions of Radio Receiver, WiFi and Bluetooth Analysis, Thermal Imaging.
The only difference between WaveSentry and WaveSentry Pro is the thermal imaging. Because the WaveSentry Pro has a thermal imaging camera.

Note:    
- The firmware used is customized. If you burn the ESP32 Marauder firmware yourself, the radio and thermal imaging functions will not be available.  
- The firmware for WaveSentry is open source.  
- The firmware for WaveSentry Pro is not open source currently.

# Where to buy
[OpenSourceSDRLab](https://opensourcesdrlab.com/products/aifw-wavesentry-esp32) official website.

# Videos
[<img alt="AIFW WaveSentry Portable ESP32 Multi-Tool" src="XXX" width="701">](https://www.youtube.com/watch?v=veseDgtHWbk)

# Functions
Note: The current firmware version of this product has removed the aggressive features in ESP32 Marauder and only retained the features suitable for security testing.

|                 |                     | Function Name        | WaveSentry        | WaveSentry Pro    |
|-----------------|---------------------|----------------------|-------------------|-------------------|
| WiFi            | Sniffers            |                      |                   |                   |
|                 |                     | Probe Request Sniff  | Support           | Support           |
|                 |                     | Beacon Sniff         | Support           | Support           |
|                 |                     | Packet Montor        | Support           | Support           |
|                 |                     | Scan APs             | Support           | Support           |
|                 |                     | Raw Capture          | Support           | Support           |
|                 |                     | Station Sniff        | Support           | Support           |
|                 |                     | Signal Monitor       | Support           | Support           |
| Bluetooth       | Sniffers            |                      |                   |
|                 |                     | Bluetooth Sniffer    | Support           | Support           |
|                 |                     | Flipper Sniff        | Support           | Support           |
|                 |                     | Airtag Sniff         | Support           | Support           |
| **Thermal Image** | **Thermal Image** |                      |                   |                   |
|                   |                   |  **Thermal Image**   | **Does not support**  | **Support**       |
| Radio Receiver  | Radio Receiver      |                      |                   |                   |
|                 |                     | FM                   | Support           | Support           |
|                 |                     | AM                   | Support           | Support           |

