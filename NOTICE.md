# Third-party notices

This repository and its release files contain work by OpenSourceSDRLab together with third-party software. The Apache License 2.0 in [LICENSE](LICENSE) applies **only** to the files created by OpenSourceSDRLab:

- `README.md`, `NOTICE.md`, `docs/`, `hardware/`, `images/`
- the WaveSentry-specific source files and changes in `WaveSentry_Community/` and `WaveSentry-V2.0/`: the radio receiver (`RadioReceiver.*`), the LVGL user interface and image files (`WaveSentry-V2.0/src/image/`), the board configuration and the changes to the files listed below

All other files keep their original copyright notices and licences:

| Component | Files | Owner | Licence |
|---|---|---|---|
| ESP32 Marauder (application structure, Wi-Fi/Bluetooth scanning, menus, display, command line, settings, SD card, GPS and battery interfaces) | `Assets.h`, `BatteryInterface.*`, `Buffer.*`, `CommandLine.*`, `Display.*`, `GpsInterface.*`, `MenuFunctions.*`, `SDInterface.*`, `Switches.*`, `WiFiBleScan.*` (from `WiFiScan.*`), `configs.h`, `lang_var.h`, `settings.*`, `utils.h`, `wavesentry_community.ino` (from `esp32_marauder.ino`), in both firmware folders, modified by OpenSourceSDRLab | Just Call Me Koko, <https://github.com/justcallmekoko/ESP32Marauder> | MIT (text below) |
| PU2CLR SI4735 Arduino library | `SI4735.cpp`, `SI4735.h` | Ricardo Lima Caratti (PU2CLR) | MIT, as stated in the file headers |
| Rotary encoder library | `Rotary.cpp`, `Rotary.h` | Ben Buxton | GPL-3.0, as stated in the file header |

Libraries that are not stored in this repository but are linked into the firmware when it is built: Arduino core for ESP32 and ESP-IDF (Espressif, Apache-2.0 and others), LVGL v7 (MIT), TFT_eSPI (Bodmer, FreeBSD/MIT), NimBLE-Arduino (Apache-2.0), ArduinoJson (MIT), LinkedList (MIT), JPEGDecoder, MicroNMEA (LGPL-2.1), EspSoftwareSerial (LGPL-2.1).

Because `Rotary.cpp` is licensed under GPL-3.0, a firmware binary built from these sources is distributed under the terms of the GPL-3.0 as a whole.

The schematic in `hardware/` describes the WaveSentry hardware designed for OpenSourceSDRLab.

## ESP32 Marauder licence

```
MIT License

Copyright (c) 2020 Just Call Me Koko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

"Espressif", "ESP32", "Silicon Labs", "Melexis" and "Flipper" are trademarks of their respective owners. They are used here only to describe compatibility and do not imply endorsement.
