#pragma once

#ifndef configs_h

  #define configs_h
  //// BOARD TARGETS
  //// END BOARD TARGETS

  #define FIRMWARE_VERSION "v1.1"

  //// HARDWARE NAMES
    #define HARDWARE_NAME "Wave Sentry"
  //// END HARDWARE NAMES

 //// BOARD FEATURES
    #define HAS_BATTERY
    #define HAS_BT
    #define HAS_BT_REMOTE
    #define HAS_BUTTONS
    #define HAS_NEOPIXEL_LED
    #define HAS_SCREEN
    #define HAS_FULL_SCREEN
    #define HAS_SD
    #define USE_SD
    #define HAS_GPS

  //// END BOARD FEATURES


  //// BUTTON DEFINITIONS
  #ifdef HAS_BUTTONS
      #define L_BTN -1
      #define C_BTN 0   //flash button is 0
      #define U_BTN -1
      #define R_BTN -1
      #define D_BTN -1
      //lcd button 25
      //using scope, I found that only IO14 is used, IO2 isn't, when rotating, IO14 will toggle no matter which direction

      //#define HAS_L
      //#define HAS_R
      //#define HAS_U
      //#define HAS_D
      #define HAS_C

      #define L_PULL true
      #define C_PULL true //flash button: true <-> gnd, false <-> 3v3 
      #define U_PULL true //true is internal pullup, false is internal pulldown. tried true, it can boot with the battery, but no square wave
      #define R_PULL true
      #define D_PULL true 

      //lcd button: false <-> 3v3, true <-> floating. I tried both true and false for D_PULL, neither is working

  #endif
  //// END BUTTON DEFINITIONS

  //// DISPLAY DEFINITIONS
  #ifdef HAS_SCREEN
      #define SCREEN_CHAR_WIDTH 40
      #define HAS_ILI9341 //by s, it seems that ILI9341 no need to define the spi of tft, nor BL or touch_cs, because they are all defined in user_setup.h of TFT_eSPI, but BL isn't useful
    
      #define BANNER_TEXT_SIZE 2

      #ifndef TFT_WIDTH
        #define TFT_WIDTH 240
      #endif

      #ifndef TFT_HEIGHT
        #define TFT_HEIGHT 320
      #endif

      #define TFT_DIY
    
      #define SCREEN_WIDTH TFT_WIDTH
      #define SCREEN_HEIGHT TFT_HEIGHT
      #define HEIGHT_1 TFT_WIDTH
      #define WIDTH_1 TFT_HEIGHT
      #define STANDARD_FONT_CHAR_LIMIT (TFT_WIDTH/6) // number of characters on a single line with normal font
      #define TEXT_HEIGHT 16 // Height of text to be printed and scrolled
      #define BOT_FIXED_AREA 0 // Number of lines in bottom fixed area (lines counted from bottom of screen)
      #define TOP_FIXED_AREA 48 // Number of lines in top fixed area (lines counted from top of screen)
      #define YMAX 320 // Bottom of screen area
      #define minimum(a,b)     (((a) < (b)) ? (a) : (b))
      //#define MENU_FONT NULL
      #define MENU_FONT &FreeMono9pt7b // Winner
      //#define MENU_FONT &FreeMonoBold9pt7b
      //#define MENU_FONT &FreeSans9pt7b
      //#define MENU_FONT &FreeSansBold9pt7b
      #define BUTTON_SCREEN_LIMIT 12
      #define BUTTON_ARRAY_LEN 12
      #define STATUS_BAR_WIDTH 16
      #define LVGL_TICK_PERIOD 6

      #define FRAME_X 100
      #define FRAME_Y 64
      #define FRAME_W 120
      #define FRAME_H 50
    
      // Red zone size
      #define REDBUTTON_X FRAME_X
      #define REDBUTTON_Y FRAME_Y
      #define REDBUTTON_W (FRAME_W/2)
      #define REDBUTTON_H FRAME_H
    
      // Green zone size
      #define GREENBUTTON_X (REDBUTTON_X + REDBUTTON_W)
      #define GREENBUTTON_Y FRAME_Y
      #define GREENBUTTON_W (FRAME_W/2)
      #define GREENBUTTON_H FRAME_H
    
      #define STATUSBAR_COLOR 0x4A49
    
      #define KIT_LED_BUILTIN 13
  #endif
  //// END DISPLAY DEFINITIONS

  //// MENU DEFINITIONS
    #define BANNER_TIME 100
    
    #define COMMAND_PREFIX "!"
    
    // Keypad start position, key sizes and spacing
    #define KEY_X 120 // Centre of key
    #define KEY_Y 50
    #define KEY_W 240 // Width and height
    #define KEY_H 22
    #define KEY_SPACING_X 0 // X and Y gap
    #define KEY_SPACING_Y 1
    #define KEY_TEXTSIZE 1   // Font size multiplier
    #define ICON_W 22
    #define ICON_H 22
    #define BUTTON_PADDING 22
    //#define BUTTON_ARRAY_LEN 5 
  //// END MENU DEFINITIONS

  //// SD DEFINITIONS
  #if defined(USE_SD)
      #define SD_CS 12
  #endif
  //// END SD DEFINITIONS

  //// SCREEN STUFF
  #ifndef HAS_SCREEN

    #define TFT_WHITE 0
    #define TFT_CYAN 0
    #define TFT_BLUE 0
    #define TFT_RED 0
    #define TFT_GREEN 0
    #define TFT_GREY 0
    #define TFT_GRAY 0
    #define TFT_MAGENTA 0
    #define TFT_VIOLET 0
    #define TFT_ORANGE 0
    #define TFT_YELLOW 0
    #define STANDARD_FONT_CHAR_LIMIT 40
    #define FLASH_BUTTON -1

    #include <FS.h>
    #include <functional>
    #include <LinkedList.h>
    #include "SPIFFS.h"
    #include "Assets.h"

  #endif
  //// END SCREEN STUFF

  //// MEMORY LOWER LIMIT STUFF
  // These values are in bytes
    #define MEM_LOWER_LIM 20000
  //// END MEMORY LOWER LIMIT STUFF

  //// GPS STUFF
  #ifdef HAS_GPS
      #define GPS_SERIAL_INDEX 2
      #define GPS_TX 4
      #define GPS_RX 13
      #define mac_history_len 512
  #endif
  //// END GPS STUFF

  //// BATTERY STUFF
  #ifdef HAS_BATTERY
      #define I2C_SDA 33
      #define I2C_SCL 22
  #endif

  //// WAVESENTRY TITLE STUFF
    #define WAVESENTRY_TITLE_BYTES 13578
  //// END WAVESENTRY TITLE STUFF

  #define ENCODER_PIN_A 2
  #define ENCODER_PIN_B 14
#endif
