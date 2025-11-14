#pragma once

#ifndef RadioReceiver_h
#define RadioReceiver_h

#include "configs.h"

#ifdef HAS_SCREEN
  #include "Display.h"
#endif

#include <Wire.h>


#include "SI4735.h"


#define SI4735_ADDR 0x63


#ifdef HAS_SCREEN
  extern Display display_obj;
#endif

class RadioReceiver {

  private:
    void showStatus();
  public:
    bool supported = false;
    bool scanning = false;
    int rotary_encoder = 0;

    void main();
    void RunSetup();
    void change_screen();
    void stop_screen();
    bool isConnected();

};

#endif
