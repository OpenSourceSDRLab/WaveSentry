---
title: WaveSentry Quick Start Guide
product: WaveSentry
doc_id: OSSDRLAB-WaveSentry-QSG
version: 1.0
date: 2026-11-12
repo: https://github.com/OpenSourceSDRLab/WaveSentry
---

<!-- ossl:header -->
<p><a href="https://www.opensourcesdrlab.com"><img src="../images/OpenSourceSDRLab-banner.jpg" alt="OpenSourceSDRLab" width="100%"></a></p>

# WaveSentry Quick Start Guide

| Product | Document | Version | Date |
|---|---|---|---|
| WaveSentry, WaveSentry Pro | OSSDRLAB-WaveSentry-QSG | 1.0 | 2026-11-12 |
<!-- /ossl:header -->

## 1. Overview

The WaveSentry is a portable ESP32 multi-tool with an AM/FM radio receiver and passive Wi-Fi and Bluetooth analysis functions. The WaveSentry Pro adds an MLX90640 thermal imaging camera. Both run firmware derived from the ESP32 Marauder project.

This guide shows how to update the firmware and how to build the open-source WaveSentry firmware from the sources in this repository.

## 2. What you need

| Item | Notes |
|---|---|
| WaveSentry or WaveSentry Pro | |
| USB-C cable | data cable, not a charge-only cable |
| Computer | Windows, macOS or Linux |
| Firmware | `WaveSentry-Pro_V2.4_firmware.zip` from the [Releases](../../../releases) page, or the `WaveSentry-R1` build from the official Bruce firmware releases |
| ESP32 flashing tool | Espressif Flash Download Tool (Windows) or Espressif `esptool` (all systems) |
| To build from source | PlatformIO (for `WaveSentry-V2.0/`) or the Arduino IDE with the ESP32 board package (for `WaveSentry_Community/`) |

## 3. Controls and connectors

| Item | Function |
|---|---|
| Power switch (ON / OFF) | switches the battery supply |
| Rotary knob | scrolls through menus and tunes the radio |
| RESET button | restarts the ESP32 |
| FLASH button | holds GPIO0 low; keep it pressed while pressing RESET to enter the boot loader |
| USB-C | charging, serial console and firmware updates (CP2102 USB-UART bridge) |
| SMA connector | antenna input of the AM/FM receiver |
| 3.5 mm jack | headphone output |
| microSD slot | captures, screenshots and thermal images |
| Thermal camera (Pro) | MLX90640 sensor on the back |

See `hardware/WaveSentry_Schematic.pdf` for the full schematic.

## 4. Update the firmware

1. Unzip `WaveSentry-Pro_V2.4_firmware.zip`. It contains `bootloader.bin`, `partitions.bin` and `firmware.bin`.

2. Switch the WaveSentry on and connect it to the computer with the USB-C cable. If the flashing tool cannot connect, hold **FLASH**, press and release **RESET**, then release **FLASH**.

3. Write the files with these settings: chip **ESP32**, SPI speed **80 MHz**, SPI mode **DIO**, baud rate **921600**.

    | File | Offset |
    |---|---|
    | `bootloader.bin` | `0x1000` |
    | `partitions.bin` | `0x8000` |
    | `firmware.bin` | `0x10000` |

4. Press **RESET**. The WaveSentry restarts with the new firmware.

> **Tip:** with `esptool` the same step is one command (replace the port name):
>
> `esptool --chip esp32 --port <PORT> --baud 921600 write_flash --flash_mode dio --flash_freq 80m 0x1000 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin`

The Bruce firmware is a single merged file: write `Bruce-WaveSentry-R1.bin` at offset `0x0`.

## 5. Build the WaveSentry firmware from source

The repository contains two versions of the open-source WaveSentry firmware (without the thermal camera):

| Folder | User interface | Build system |
|---|---|---|
| `WaveSentry-V2.0/` | LVGL touch interface | PlatformIO, environment `esp32dev`, partition table `min_spiffs.csv` |
| `WaveSentry_Community/` | original interface | Arduino IDE, board **LOLIN D32**, flash frequency 80 MHz, partition scheme **Minimal SPIFFS** |

Both need these libraries: LVGL 7.x, TFT_eSPI, NimBLE-Arduino, ArduinoJson, LinkedList, JPEGDecoder, MicroNMEA and EspSoftwareSerial.

TFT_eSPI must be configured for the WaveSentry display (ILI9341, 240 × 320) in its `User_Setup.h`:

| Setting | GPIO |
|---|---|
| `TFT_MOSI` | 23 |
| `TFT_MISO` | 19 |
| `TFT_SCLK` | 18 |
| `TFT_CS` | 17 |
| `TFT_DC` | 16 |
| `TFT_RST` | 5 |
| `TFT_BL` | 32 |
| `TOUCH_CS` | 21 |

Other pins used by the firmware (`configs.h`, `RadioReceiver.cpp`): SD card CS 12, I2C SDA 33 / SCL 22 (SI4732 radio, MLX90640, fuel gauge), rotary encoder A 2 / B 14, GPS TX 4 / RX 13, amplifier enable 26, mute 27, radio reset 25.

## 6. Support

- Email: support@opensourcesdrlab.com
- Forum: <https://forum.opensourcesdrlab.com>
- Discord: <https://discord.gg/nnxY6DkmvT>
- Blog and user manuals: <https://blog.opensourcesdrlab.com>

<!-- ossl:footer -->
---
<sub>© 2026 OpenSourceSDRLab. All rights reserved. · <a href="https://www.opensourcesdrlab.com">www.opensourcesdrlab.com</a></sub>
<!-- /ossl:footer -->
