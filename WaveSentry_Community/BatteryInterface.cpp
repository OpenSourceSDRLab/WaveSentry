#include "BatteryInterface.h"
#include "lang_var.h"
BatteryInterface::BatteryInterface() {
  
}

bool writeToRegisterMulti(byte I2C_ADDRESS, byte reg, uint16_t value,int length) {
  byte data[2];
  data[0] = ((value & (uint16_t)0x00FF));
  data[1] = ((value & (uint16_t)0xFF00) >> 8);
  
  Wire.beginTransmission(I2C_ADDRESS);
  Wire.write(reg);            
  for (int i = 0; i < length; i++) {
    Wire.write(data[i]);
  }
  return Wire.endTransmission();
}

void BatteryInterface::main(uint32_t currentTime) {
  if (currentTime != 0) {
    if (currentTime - initTime >= 3000) {
      //Serial.println("Checking Battery Level");
      this->initTime = millis();
      int8_t new_level = this->getBatteryLevel();
      //this->battery_level = this->getBatteryLevel();
      if (this->battery_level != new_level) {
        Serial.println(text00 + (String)new_level);
        this->battery_level = new_level;
        Serial.println("Battery Level: " + (String)this->battery_level);
      }
    }
  }
}

void BatteryInterface::RunSetup() {
  byte error;
  byte addr;

  #ifdef HAS_BATTERY

    Wire.begin(I2C_SDA, I2C_SCL);
    Wire.setClock(400000);

    Serial.println("Checking for battery monitors...");

    Wire.beginTransmission(IP5306_ADDR);
    error = Wire.endTransmission();

    if (error == 0) {
      Serial.println("Detected IP5306");
      this->has_ip5306 = true;
      this->i2c_supported = true;
    }

    Wire.beginTransmission(MAX17048_ADDR);
    error = Wire.endTransmission();

    if (error == 0) {
      if (maxlipo.begin()) {    //by s important, delete will cause reboot
        Serial.println("Detected MAX17048");
        this->has_max17048 = true;
        this->i2c_supported = true;
      }
    }

    Wire.beginTransmission(MAX17055_ADDR);
    error = Wire.endTransmission();

    if (error == 0) {
      Serial.println("Detected MAX17055");
      this->has_max17055 = true;
      this->i2c_supported = true;

      //configuration
      writeToRegisterMulti(MAX17055_ADDR, 0x1D, 0x0000, 2);
      writeToRegisterMulti(MAX17055_ADDR, 0xBB, 0x0218, 2);
      writeToRegisterMulti(MAX17055_ADDR, 0xBA, 0x0000, 2);

      //capacity 1000mAh
      writeToRegisterMulti(MAX17055_ADDR, 0x18, 0x07D0, 2);

      //model cfg
      uint16_t _Data_Set = 0x00;
      bitSet(_Data_Set, 10); //Vchg true 
      
      bitClear(_Data_Set, 4); //model_id 2
      bitSet(_Data_Set, 5);
      bitClear(_Data_Set, 6);
      bitClear(_Data_Set, 7);

      writeToRegisterMulti(MAX17055_ADDR, 0xDB, _Data_Set, 2);

      //set empty recovery voltage
      // Set Empty Raw
      uint32_t _Raw_Empty_Voltage = (uint32_t(3.0 * 1000) / 10);
      _Raw_Empty_Voltage = (_Raw_Empty_Voltage << 7) & 0xFF80;
      // Set Recovery Raw
      uint32_t _Raw_Recovery_Voltage = ((uint32_t(4.1 * 1000) / 40) & 0x7F);
      // Set Raw Data
      uint32_t _Raw_Voltage = _Raw_Empty_Voltage | _Raw_Recovery_Voltage;
      writeToRegisterMulti(MAX17055_ADDR, 0x3A, (uint16_t)_Raw_Voltage, 2);

      //set termination condition
      uint32_t _Raw_Termination_Voltage = 0x0280;
      writeToRegisterMulti(MAX17055_ADDR, 0x1E, (uint16_t)_Raw_Termination_Voltage, 2);


      

    }
      
      
    

    //s actually is using MAX17055 on SDA_IO33 SCL_IO22
    //to check everything on IIC bus on startup
    /*for(addr = 1; addr < 127; addr++ ) {
      Wire.beginTransmission(addr);
      error = Wire.endTransmission();

      if (error == 0)
      {
        Serial.print("I2C device found at address 0x");
        
        if (addr<16)
          Serial.print("0");

        Serial.println(addr,HEX);
      }
    }*/

    
    this->initTime = millis();
  #endif
}

int8_t BatteryInterface::getBatteryLevel() {

  if (this->has_ip5306) {
    Wire.beginTransmission(IP5306_ADDR);
    Wire.write(0x78);
    if (Wire.endTransmission(false) == 0 &&
        Wire.requestFrom(IP5306_ADDR, 1)) {
      this->i2c_supported = true;
      switch (Wire.read() & 0xF0) {
        case 0xE0: return 25;
        case 0xC0: return 50;
        case 0x80: return 75;
        case 0x00: return 100;
        default: return 0;
      }
    }
    this->i2c_supported = false;
    return -1;
  }


  if (this->has_max17048) {
    float percent = this->maxlipo.cellPercent();

    // Sometimes we dumb
    if (percent >= 100)
      return 100;
    else if (percent <= 0)
      return 0;
    else
      return percent;
  }

  
  if (this->has_max17055) {
    /*byte buffer[2];
    
    Wire.beginTransmission(MAX17055_ADDR);
    Wire.write(0x09);
    if (Wire.endTransmission(false) != 0) {
      return 0;                 
    }
    Wire.requestFrom(MAX17055_ADDR, 2);
    if (Wire.available() == 2) {
        for (int i = 0; i < 2; i++) {
          buffer[i] = Wire.read();        
        }
    }
    uint16_t Measurement_Raw = ((uint16_t)buffer[1] << 8) | (uint16_t)buffer[0];

    
    float voltage = ((float)Measurement_Raw * 1.25 / 16) / 1000;
    float percent = (voltage - 3.1) * 100;*/

    uint8_t MAX17055_Data[2];

    Wire.beginTransmission(MAX17055_ADDR);
    Wire.write(0x0E);
    if (Wire.endTransmission(false) != 0) {
      return 0;                 
    }
    Wire.requestFrom(MAX17055_ADDR, 2);
    if (Wire.available() == 2) {
        for (int i = 0; i < 2; i++) {
          MAX17055_Data[i] = Wire.read();        
        }
    }

    float percent = ((float)MAX17055_Data[1] + (float)MAX17055_Data[0] / 256);
    percent = percent * 1.17; //to show 100% when fully charged

    

    // Sometimes we dumb
    if (percent >= 100)
      return 100;
    else if (percent <= 0)
      return 0;
    else
      return percent;
  }
  
}
