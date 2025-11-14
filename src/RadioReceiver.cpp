#include "RadioReceiver.h"

#define RESET_PIN 25       // pin25 can be used as output; pin35 can only be input
                        //the board I have is pin25 <-> audio_rst indeed, so I might be able to control it via software, instead of connect real wire
#define MUTE_PIN 27
#define AMP_EN 26
#define FLASH_BUTTON 0
#define ADC_IN 34

#define AM_FUNCTION 1
#define FM_FUNCTION 0
bool current_function;

uint16_t currentFrequency;
uint16_t previousFrequency;
uint16_t frequencyStep = 10;
uint8_t bandwidthIdx = 0;
const char *bandwidth[] = {"6", "4", "3", "2", "1", "1.8", "2.5"};

uint16_t currentSNR;
uint16_t maxFreq;
uint16_t minFreq;

SI4735 si4735;
unsigned char last_pinstate;

int editing_item = 1;
int current_value = 20;

static uint32_t scanTime = millis();
static uint32_t displayTime = millis();

//#include <TFT_eSPI_Button.h>

#ifdef HAS_BUTTONS
  #include "Switches.h"
  
  #if (U_BTN >= 0)
    Switches u_btn = Switches(U_BTN, 1000, U_PULL);
  #endif
  #if (D_BTN >= 0)
    Switches d_btn = Switches(D_BTN, 1000, D_PULL);
  #endif
  #if (L_BTN >= 0)
    Switches l_btn = Switches(L_BTN, 1000, L_PULL);
  #endif
  #if (R_BTN >= 0)
    Switches r_btn = Switches(R_BTN, 1000, R_PULL);
  #endif
  #if (C_BTN >= 0)
    Switches c_btn = Switches(C_BTN, 1000, C_PULL);
  #endif

#endif


// Show current frequency
void RadioReceiver::showStatus()
{
  si4735.getStatus();
  si4735.getCurrentReceivedSignalQuality();
  Serial.print("You are tuned on ");
  if (si4735.isCurrentTuneFM())
  {
    Serial.print(String(currentFrequency / 100.0, 2));
    Serial.print("MHz ");
    Serial.print((si4735.getCurrentPilot()) ? "STEREO" : "MONO");
  }
  else
  {
    Serial.print(currentFrequency);
    Serial.print("kHz");
  }
  Serial.print(" [SNR:");
  Serial.print(si4735.getCurrentSNR());
  Serial.print("dB");

  Serial.print(" Signal:");
  Serial.print(si4735.getCurrentRSSI());
  Serial.println("dBuV]");
}

void RadioReceiver::RunSetup() {
  Wire.begin(I2C_SDA, I2C_SCL);

  /*if (isConnected() == false)
  {
    this->supported = false;
    Serial.println("SI4735 not detected at default I2C address. Please check wiring. Freezing.");
  }
  else
  {*/
    this->supported = true;
  
}

void RadioReceiver::change_screen(){
    display_obj.tft.setTextWrap(false);
    display_obj.tft.setFreeFont(NULL);
    display_obj.tft.setCursor(0, TFT_HEIGHT / 3);
    display_obj.tft.setTextSize(1);
    display_obj.tft.setTextColor(TFT_WHITE);


    pinMode(AMP_EN, OUTPUT);
    digitalWrite(AMP_EN, HIGH);
    pinMode(MUTE_PIN, OUTPUT);
    digitalWrite(MUTE_PIN, LOW);

    pinMode(ADC_IN, INPUT);

    Serial.println("AM and FM station tuning test.");
  
    delay(500);

    digitalWrite(MUTE_PIN, HIGH);

    si4735.setup(25, FM_FUNCTION);

    // Starts default radio function and band (FM; from 64 to 108 MHz; 103.7 MHz; step 100kHz)
    si4735.setFM(6400, 10800, 10370, 10);
    delay(500);
    digitalWrite(MUTE_PIN, LOW);

    current_function = FM_FUNCTION;
    
    currentFrequency = previousFrequency = si4735.getFrequency();

    current_value = 20;
    si4735.setVolume(current_value);

    delay(500);
    showStatus();
    

    /*delay(1000);
    
    si4735.setFrequency(10170);
    
    delay(500);
    showStatus();*/

    this->scanning = true;

    //display_obj.tftDrawSwitchButton();
    display_obj.tft.drawRect(39,211,18,18, TFT_WHITE);
    display_obj.tft.drawRect(39,231,18,18, TFT_WHITE);
    display_obj.tft.drawRect(39,251,18,18, TFT_WHITE);
    display_obj.tft.drawRect(39,271,18,18, TFT_WHITE);


    display_obj.tft.fillRect(40,232,16,16, TFT_GREEN);

    si4735.setFM(6400, 10800, 10370, 10);


}

void RadioReceiver::stop_screen(){

    digitalWrite(AMP_EN, LOW);
    digitalWrite(MUTE_PIN, HIGH);
    digitalWrite(RESET_PIN, LOW);

    
    this->scanning = false;
    editing_item = 1; //when exiting change editing to default
}

void RadioReceiver::main() {
  //this main is called by loop of .ino, so pratically this function is in a while loop
  if (this->supported) {
     // do something here
     // like serial commander or scope view

    if (millis() - displayTime >= 100) 
    {
       //update status
       currentFrequency = si4735.getCurrentFrequency();   //this is necessary to print frequency
       si4735.getStatus();
       si4735.getCurrentReceivedSignalQuality();
       currentSNR = si4735.getCurrentSNR();

       char charSNR[3];
       dtostrf(currentSNR, 2, 0, charSNR);  
       char charStep[3];
       dtostrf(frequencyStep, 2, 0, charStep);  


       display_obj.tft.setCursor(60, 212);
       display_obj.tft.setTextColor(TFT_WHITE, TFT_BLACK);
       display_obj.tft.setTextFont(2);
       display_obj.tft.setTextSize(1);

       if (current_function == AM_FUNCTION)
       {
          display_obj.tft.print("Mode: AM");
       }
       else
       {
          display_obj.tft.print("Mode: FM");
       }

       display_obj.tft.setCursor(60, 232);
       display_obj.tft.setTextColor(TFT_WHITE, TFT_BLACK);
       display_obj.tft.setTextFont(2);
       display_obj.tft.setTextSize(1);
       display_obj.tft.print("Volume: " + String(current_value));
       
       display_obj.tft.setCursor(60, 252);
       display_obj.tft.setTextColor(TFT_WHITE, TFT_BLACK);
       display_obj.tft.setTextFont(2);
       display_obj.tft.setTextSize(1);
       if (current_function == FM_FUNCTION)
       {
          display_obj.tft.print("Freq: " + String(currentFrequency / 100.0, 2) + " MHz" + " SNR: " + charSNR); //in future, should handle SNR<10. Do similar as currentFrequency
       }
       else
       {
          display_obj.tft.print("Freq: " + String(currentFrequency/1000.0, 3) + " MHz" + " SNR: " + charSNR);
       }

       display_obj.tft.setCursor(60, 272);
       display_obj.tft.setTextColor(TFT_WHITE, TFT_BLACK);
       display_obj.tft.setTextFont(2);
       display_obj.tft.setTextSize(1);

       const char* str1 = "Step: ";
       char result[100];
       snprintf(result, sizeof(result), "%s%s", str1, charStep);
       display_obj.tft.print(result);

       displayTime = millis();
    }

    if (millis() - scanTime >= 5) 
    {
      //rotate encoder handler
      unsigned char pinstate = (digitalRead(ENCODER_PIN_A) << 1) | digitalRead(ENCODER_PIN_B);
      if (last_pinstate != pinstate)
      {
          if (rotary_encoder < 0)
          {
            //si4735.frequencyUp(); // not working
            if (editing_item == 0)
            {
              maxFreq = 10800;
              minFreq = 6400;
              digitalWrite(MUTE_PIN, HIGH);
              si4735.setFM(6400, 10800, 10370, 10); //from 64MHz to 108MHz, default 103.7MHz, step 10 is 100kHz
              current_function = FM_FUNCTION;
              digitalWrite(MUTE_PIN, LOW);
              display_obj.tft.fillRect(60,252,180,16, TFT_BLACK);
            }
            else if (editing_item == 1)
            {
              si4735.volumeUp();
              if(current_value < 99)
              {
                current_value++;
              }
            }
            else if (editing_item == 2)
            {
              currentFrequency = currentFrequency + frequencyStep;
              si4735.setFrequency(currentFrequency);
            }
            else if (editing_item == 3)
            {
              frequencyStep = 10;
            }
          }
          else
          {
            //si4735.frequencyDown(); //not working
            if (editing_item == 0)
            {
              maxFreq = 30000;
              minFreq = 150;
              digitalWrite(MUTE_PIN, HIGH);
              si4735.setAM(150, 30000, 10000, 10); //from 150kHz to 30MHz, default 10MHz, step 10 is 10kHz
              current_function = AM_FUNCTION;
              digitalWrite(MUTE_PIN, LOW);
              display_obj.tft.fillRect(60,252,180,16, TFT_BLACK);
            }
            else if (editing_item == 1)
            {
              si4735.volumeDown();
              if(current_value > 10)
              {
                current_value--;
              }
            }
            else if (editing_item == 2)
            {
              currentFrequency = currentFrequency - frequencyStep;
              si4735.setFrequency(currentFrequency);
            }
            else if (editing_item == 3)
            {
              frequencyStep = 1;
            }
          }
          last_pinstate = pinstate;
      }


      boolean pressed = false;
      uint16_t t_x = 0, t_y = 0; // To store the touch coordinates
      // touch handler
      pressed = display_obj.tft.getTouch(&t_x, &t_y);
  
      if (pressed) {
        if (t_y > 212 && t_y < 228)
        {
          editing_item = 0;
          display_obj.tft.fillRect(40,212,16,16, TFT_GREEN);
          display_obj.tft.fillRect(40,232,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,252,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,272,16,16, TFT_BLACK);
        }    
        else if (t_y > 232 && t_y < 248)
        {
          editing_item = 1;
          display_obj.tft.fillRect(40,212,16,16, TFT_BLACK);          
          display_obj.tft.fillRect(40,232,16,16, TFT_GREEN);
          display_obj.tft.fillRect(40,252,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,272,16,16, TFT_BLACK);

        }
        else if (t_y > 252 && t_y <268)
        {
          editing_item = 2;
          display_obj.tft.fillRect(40,212,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,232,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,252,16,16, TFT_GREEN);
          display_obj.tft.fillRect(40,272,16,16, TFT_BLACK);
        }
        else if (t_y > 272 && t_y <288)
        {
          editing_item = 3;
          display_obj.tft.fillRect(40,212,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,232,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,252,16,16, TFT_BLACK);
          display_obj.tft.fillRect(40,272,16,16, TFT_GREEN);
        }
        
      }

      scanTime = millis();
    }
   
  }
   
}

//Returns true if the SI4735 is detected on the I2C bus
bool RadioReceiver::isConnected(){
  Wire.beginTransmission(SI4735_ADDR);
  if (Wire.endTransmission() != 0)
    return false; //Sensor did not ACK
  return true;
}
