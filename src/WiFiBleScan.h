#pragma once

#ifndef WiFiBleScan_h
#define WiFiBleScan_h

#include "configs.h"
#include "utils.h"

#include <ArduinoJson.h>
#include <algorithm>
#include <vector>

#ifdef HAS_BT
  #include <NimBLEDevice.h>
#endif

#include <WiFi.h>
#include <math.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#ifdef HAS_BT
  #include "esp_bt.h"
#endif
#ifdef HAS_SCREEN
  #include "Display.h"
#endif
#ifdef HAS_SD
  #include "SDInterface.h"
#endif
#include "Buffer.h"
#ifdef HAS_BATTERY
  #include "BatteryInterface.h"
#endif
#ifdef HAS_GPS
  #include "GpsInterface.h"
#endif
#include "settings.h"
#include "Assets.h"

#define bad_list_length 3

#define OTA_UPDATE 100
#define SHOW_INFO 101
#define ESP_UPDATE 102
#define WIFI_SCAN_OFF 0
#define WIFI_SCAN_PROBE 1
#define WIFI_SCAN_AP 2
#define WIFI_SCAN_DEAUTH 5
#define WIFI_SCAN_ALL 6
#define WIFI_PACKET_MONITOR 7
#define BT_SCAN_ALL 10
#define WIFI_SCAN_ESPRESSIF 12
#define LV_JOIN_WIFI 13
#define LV_ADD_SSID 14
#define WIFI_SCAN_TARGET_AP 16
#define LV_SELECT_AP 17
#define WIFI_SCAN_TARGET_AP_FULL 22
#define WIFI_SCAN_RAW_CAPTURE 25
#define WIFI_SCAN_STATION 26
#define WIFI_SCAN_SIG_STREN 29
#define WIFI_SCAN_GPS_DATA 31
#define WIFI_SCAN_GPS_NMEA 40
#define BT_SCAN_AIRTAG 43
#define BT_SCAN_FLIPPER 45

#define GRAPH_REFRESH 100

#define MAX_CHANNEL 14

#ifdef HAS_SCREEN
  extern Display display_obj;
#endif
#ifdef HAS_SD
  extern SDInterface sd_obj;
#endif
#ifdef HAS_GPS
  extern GpsInterface gps_obj;
#endif
extern Buffer buffer_obj;
#ifdef HAS_BATTERY
  extern BatteryInterface battery_obj;
#endif
extern Settings settings_obj;

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

struct AirTag {
    String mac;                  // MAC address of the AirTag
    std::vector<uint8_t> payload; // Payload data
    uint16_t payloadSize;
    bool selected;
};

struct Flipper {
  String mac;
  String name;
};

struct ssid {
  String essid;
  uint8_t channel;
  uint8_t bssid[6];
  bool selected;
};

struct AccessPoint {
  String essid;
  uint8_t channel;
  uint8_t bssid[6];
  bool selected;
  LinkedList<char>* beacon;
  char rssi;
  LinkedList<uint8_t>* stations;
};

class WiFiBleScan
{
  private:
    struct mac_addr mac_history[mac_history_len];

    // Settings
    uint mac_history_cursor = 0;
    uint8_t channel_hop_delay = 1;
    bool force_pmkid = false;
    bool force_probe = false;
    bool save_pcap = false;
  
    int x_pos; //position along the graph x axis
    float y_pos_x; //current graph y axis position of X value
    float y_pos_x_old = 120; //old y axis position of X value
    float y_pos_y; //current graph y axis position of Y value
    float y_pos_y_old = 120; //old y axis position of Y value
    float y_pos_z; //current graph y axis position of Z value
    float y_pos_z_old = 120; //old y axis position of Z value
    int midway = 0;
    byte x_scale = 1; //scale of graph x axis, controlled by touchscreen buttons
    byte y_scale = 1;

    bool do_break = false;

    bool wsl_bypass_enabled = false;

    //int num_beacon = 0; // GREEN
    //int num_probe = 0; // BLUE
    //int num_deauth = 0; // RED

    uint32_t initTime = 0;
    bool run_setup = true;
    void initWiFi(uint8_t scan_mode);
    uint8_t bluetoothScanTime = 5;
    int packets_sent = 0;
    const wifi_promiscuous_filter_t filt = {.filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
    #ifdef HAS_BT
      NimBLEScan* pBLEScan;
    #endif

    //String connected_network = "";
    //const String alfa = "1234567890qwertyuiopasdfghjkklzxcvbnm QWERTYUIOPASDFGHJKLZXCVBNM_";

    char* prefix = "G";

    typedef struct
    {
      int16_t fctl;
      int16_t duration;
      uint8_t da;
      uint8_t sa;
      uint8_t bssid;
      int16_t seqctl;
      unsigned char payload[];
    } __attribute__((packed)) WifiMgmtHdr;
    
    typedef struct {
      uint8_t payload[0];
      WifiMgmtHdr hdr;
    } wifi_ieee80211_packet_t;

    // barebones packet
    uint8_t packet[128] = { 0x80, 0x00, 0x00, 0x00, //Frame Control, Duration
                    /*4*/   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //Destination address 
                    /*10*/  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //Source address - overwritten later
                    /*16*/  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //BSSID - overwritten to the same as the source address
                    /*22*/  0xc0, 0x6c, //Seq-ctl
                    /*24*/  0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, //timestamp - the number of microseconds the AP has been active
                    /*32*/  0x64, 0x00, //Beacon interval
                    /*34*/  0x01, 0x04, //Capability info
                    /* SSID */
                    /*36*/  0x00
                    };

    uint8_t prob_req_packet[128] = {0x40, 0x00, 0x00, 0x00, 
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination
                                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dest
                                  0x01, 0x00, // Sequence
                                  0x00, // SSID Parameter
                                  0x00, // SSID Length
                                  /* SSID */
                                  };

    uint8_t deauth_frame_default[26] = {
                              0xc0, 0x00, 0x3a, 0x01,
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0xf0, 0xff, 0x02, 0x00
                          };

    enum EBLEPayloadType
    {
      Microsoft,
      Apple,
      Samsung,
      Google,
      FlipperZero,
      Airtag
    };

      #ifdef HAS_BT

      struct BLEData
      {
        NimBLEAdvertisementData AdvData;
        NimBLEAdvertisementData ScanData;
      };

      struct WatchModel
      {
          uint8_t value;
          const char *name;
      };

      WatchModel* watch_models = nullptr;

      static void scanCompleteCB(BLEScanResults scanResults);
      NimBLEAdvertisementData GetUniversalAdvertisementData(EBLEPayloadType type);
    #endif

    bool seen_mac(unsigned char* mac);
    bool mac_cmp(struct mac_addr addr1, struct mac_addr addr2);
    void save_mac(unsigned char* mac);
    void clearMacHistory();
    String processPwnagotchiBeacon(const uint8_t* frame, int length);

    void startWiFiAttacks(uint8_t scan_mode, uint16_t color, String title_string);

    void packetMonitorMain(uint32_t currentTime);
    void updateMidway();
    void tftDrawXScalButtons();
    void tftDrawYScaleButtons();
    void tftDrawChannelScaleButtons();
    void tftDrawColorKey();
    void tftDrawGraphObjects();
    void sendDeauthFrame(uint8_t bssid[6], int channel, String dst_mac_str = "ff:ff:ff:ff:ff:ff");
    void sendDeauthFrame(uint8_t bssid[6], int channel, uint8_t mac[6]);
    void broadcastRandomSSID(uint32_t currentTime);
    void broadcastCustomBeacon(uint32_t current_time, ssid custom_ssid);
    void broadcastCustomBeacon(uint32_t current_time, AccessPoint custom_ssid);
    void broadcastSetSSID(uint32_t current_time, const char* ESSID);
    void RunAPScan(uint8_t scan_mode, uint16_t color);
    void RunGPSInfo();
    void RunGPSNmea();
    void RunBeaconScan(uint8_t scan_mode, uint16_t color);
    void RunRawScan(uint8_t scan_mode, uint16_t color);
    void RunStationScan(uint8_t scan_mode, uint16_t color);
    void RunDeauthScan(uint8_t scan_mode, uint16_t color);
    void RunProbeScan(uint8_t scan_mode, uint16_t color);
    void RunPacketMonitor(uint8_t scan_mode, uint16_t color);
    void RunBluetoothScan(uint8_t scan_mode, uint16_t color);
    void RunLvJoinWiFi(uint8_t scan_mode, uint16_t color);
    bool checkMem();
    void parseBSSID(const char* bssidStr, uint8_t* bssid);


  public:
    WiFiBleScan();

    uint8_t set_channel = 1;

    uint8_t old_channel = 0;

    bool orient_display = false;
    bool wifi_initialized = false;
    bool ble_initialized = false;

    String free_ram = "";
    String old_free_ram = "";
    String connected_network = "";

    String dst_mac = "ff:ff:ff:ff:ff:ff";
    byte src_mac[6] = {};

    String current_mini_kb_ssid = "";

    const String alfa = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789-=[];',./`\\_+{}:\"<>?~|!@#$%^&*()";

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t ap_config;

    String security_int_to_string(int security_type);
    char* stringToChar(String string);
    void RunSetup();
    int clearSSIDs();
    int clearAPs();
    int clearAirtags();
    int clearFlippers();
    int clearStations();
    bool addSSID(String essid);
    int generateSSIDs(int count = 20);
    bool shutdownWiFi();
    bool shutdownBLE();
    bool scanning();
    String getStaMAC();
    String getApMAC();
    String freeRAM();
    void changeChannel();
    void changeChannel(int chan);
    void RunInfo();
    void RunGenerateSSIDs(int count = 20);
    void RunClearSSIDs();
    void RunClearAPs();
    void RunClearStations();
    void RunSaveAPList(bool save_as = true);
    void RunLoadAPList();
    void RunSaveATList(bool save_as = true);
    void RunLoadATList();
    void channelHop();
    uint8_t currentScanMode = 0;
    void main(uint32_t currentTime);
    void StartScan(uint8_t scan_mode, uint16_t color = 0);
    void StopScan(uint8_t scan_mode);
    void setBaseMacAddress(uint8_t macAddr[6]);

    bool save_serial = false;
    void startPcap(String file_name);
    void startLog(String file_name);

    static void getMAC(char *addr, uint8_t* data, uint16_t offset);
    static void beaconSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void rawSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void stationSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void apSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void apSnifferCallbackFull(void* buf, wifi_promiscuous_pkt_type_t type);
    static void deauthSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void beaconListSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    static void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

};
#endif
