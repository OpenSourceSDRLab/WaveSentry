#include "MenuFunctions.h"
#include "lang_var.h"
//#include "icons.h"

#ifdef HAS_SCREEN

extern const unsigned char menu_icons[][66];

extern lv_area_t g_btn_cont_area;
extern bool g_limit_to_container;
static bool g_block_lvgl = false;

PROGMEM lv_obj_t * slider_label;
PROGMEM lv_obj_t * ta1;
PROGMEM lv_obj_t * ta2;
PROGMEM lv_obj_t * save_name;

MenuFunctions::MenuFunctions()
{
	button_container = NULL;
	custom_scr = NULL;
}

// LVGL Stuff
/* Interrupt driven periodic handler */

#ifdef HAS_ILI9341
  uint8_t MenuFunctions::updateTouch(uint16_t *x, uint16_t *y, uint16_t threshold) {
    if (!display_obj.headless_mode)
      return display_obj.tft.getTouch(x, y, threshold);
    else
      return !display_obj.headless_mode;
  }

  void MenuFunctions::lv_tick_handler()
  {
    lv_tick_inc(LVGL_TICK_PERIOD);
  }
  
  /* Display flushing */
//   void my_disp_flush(lv_disp_drv_t *disp, const lv_area_t *area, lv_color_t *color_p)
//   {
//     extern Display display_obj;
//     uint16_t c;

//     // 检查刷新区域是否与状态栏重叠
//     // 如果刷新区域在状态栏内（y < TOP_FIXED_AREA），则跳过刷新
//     if (area->y2 < TOP_FIXED_AREA) {
//         // 完全在状态栏内，直接返回不刷新
//         lv_disp_flush_ready(disp);
//         return;
//     }
    
//     // 如果部分重叠，只刷新状态栏下方的部分
//     lv_area_t flush_area = *area;
//     int skip_pixels = 0;
    
//     if (area->y1 < TOP_FIXED_AREA) {
//         // 部分重叠，计算需要跳过的像素数
//         skip_pixels = (TOP_FIXED_AREA - area->y1) * (area->x2 - area->x1 + 1);
//         flush_area.y1 = TOP_FIXED_AREA;
//         // 跳过这些像素的缓冲区指针
//         color_p += skip_pixels;
//     }

//     display_obj.tft.startWrite();
//     display_obj.tft.setAddrWindow(flush_area.x1, flush_area.y1, 
//                                   (flush_area.x2 - flush_area.x1 + 1), 
//                                   (flush_area.y2 - flush_area.y1 + 1));
    
//     for (int y = flush_area.y1; y <= flush_area.y2; y++) {
//         for (int x = flush_area.x1; x <= flush_area.x2; x++) {
//             c = color_p->full;
//             display_obj.tft.writeColor(c, 1);
//             color_p++;
//         }
//     }
//     display_obj.tft.endWrite();
//     lv_disp_flush_ready(disp);
//   }
static inline bool rect_overlap(const lv_area_t* a, const lv_area_t* b) {
  return !(a->x2 < b->x1 || b->x2 < a->x1 || a->y2 < b->y1 || b->y2 < a->y1);
}
static inline void rect_intersection(lv_area_t* out, const lv_area_t* a, const lv_area_t* b) {
  out->x1 = a->x1 > b->x1 ? a->x1 : b->x1;
  out->y1 = a->y1 > b->y1 ? a->y1 : b->y1;
  out->x2 = a->x2 < b->x2 ? a->x2 : b->x2;
  out->y2 = a->y2 < b->y2 ? a->y2 : b->y2;
}

/// @brief LVGL渲染函数接口
/// @param disp 
/// @param area 
/// @param color_p 
// void my_disp_flush(lv_disp_drv_t *disp, const lv_area_t *area, lv_color_t *color_p)
// {
// 	// 如果设置不渲染就不显示菜单
// 	if (g_block_lvgl) {
// 		lv_disp_flush_ready(disp);
// 		return;
//   	}

// 	extern Display display_obj;

// 	// 屏幕可以显示的区域
// 	lv_area_t visible = { 0, 0, 240 - 1, 320 - 1 };

// 	// if(g_limit_to_container)
// 	// {
// 	// 	visible= { 0, TOP_FIXED_AREA, 240 - 1, 320 -1 };
// 	// }
// 	// else
// 	// {
// 	// 	visible= { 0, 0, 240 - 1, 320 -1 };
// 	// }
	 

// 	// 如果当前绘制区域不在可显示范围内，就不要渲染了
// 	if (!rect_overlap(area, &visible)) {
// 		lv_disp_flush_ready(disp);
// 		return;
// 	}

// 	// 给出可以渲染的区域
// 	lv_area_t flush_area;
// 	rect_intersection(&flush_area, area, &visible);

//   	// 2) 如需仅刷新 button_container，再与其相交
//   	if (g_limit_to_container) {
    
// 		if (!rect_overlap(&flush_area, &g_btn_cont_area)) 
// 		{
// 			lv_disp_flush_ready(disp);
// 			return;
// 		}
// 		rect_intersection(&flush_area, &flush_area, &g_btn_cont_area);
// 	}

// 	// 3) 计算源区域宽与起始偏移
// 	const int src_w  = area->x2 - area->x1 + 1;
// 	const int skip_y = flush_area.y1 - area->y1;
// 	const int skip_x = flush_area.x1 - area->x1;
// 	color_p += skip_y * src_w + skip_x;

// 	const int draw_w = flush_area.x2 - flush_area.x1 + 1;
// 	const int draw_h = flush_area.y2 - flush_area.y1 + 1;

// 	display_obj.tft.startWrite();
// 	display_obj.tft.setAddrWindow(flush_area.x1, flush_area.y1, draw_w, draw_h);

// 	// 4) 每行结束后前进 src_w（因为行内我们用 color_p[x] 索引访问）
// 	for (int y = 0; y < draw_h; y++) {
// 		for (int x = 0; x < draw_w; x++)
// 		{
// 			display_obj.tft.writeColor(color_p[x].full, 1);
// 		}
// 		color_p += src_w;
// 	}

// 	display_obj.tft.endWrite();
// 	lv_disp_flush_ready(disp);

// }

void my_disp_flush(lv_disp_drv_t *disp, const lv_area_t *area, lv_color_t *color_p)
{
	// 允许外部屏蔽 LVGL 刷新
	if (g_block_lvgl) {
		lv_disp_flush_ready(disp);
		return;
	}

	extern Display display_obj;

	// 旋转自适应：使用当前旋转下的宽高，避免写死 240x320
	const int scr_w = display_obj.tft.width();   // 随 setRotation() 变化
	const int scr_h = display_obj.tft.height();  // 随 setRotation() 变化

	// 仅刷新状态栏以下的可见区域（无论旋转为 0/1/2/3，y=0 顶部保持一致）
	lv_area_t visible = { 0, 0, scr_w - 1, scr_h - 1 };
	if (!rect_overlap(area, &visible)) {
		lv_disp_flush_ready(disp);
		return;
	}

	// 与可见区域求交
	lv_area_t flush_area;
	rect_intersection(&flush_area, area, &visible);

	// 如启用仅刷新容器，则进一步与容器区域求交
	if (g_limit_to_container) {
		if (!rect_overlap(&flush_area, &g_btn_cont_area)) {
			lv_disp_flush_ready(disp);
			return;
		}
		rect_intersection(&flush_area, &flush_area, &g_btn_cont_area);
	}

	// 源区域宽高（与 LVGL 传入的 area 一致）
	const int src_w = (area->x2 - area->x1 + 1);
	const int src_h = (area->y2 - area->y1 + 1);

	// 目标绘制宽高（实际要写到屏的交集）
	const int draw_w = (flush_area.x2 - flush_area.x1 + 1);
	const int draw_h = (flush_area.y2 - flush_area.y1 + 1);

	// 需要在源缓冲内跳过的偏移（以 area 左上为原点）
	const int skip_x = (flush_area.x1 - area->x1);
	const int skip_y = (flush_area.y1 - area->y1);

	// 健壮性校验，防止越界
	if (draw_w <= 0 || draw_h <= 0 ||
		src_w <= 0 || src_h <= 0 ||
		skip_x < 0 || skip_y < 0 ||
		(skip_x + draw_w) > src_w ||
		(skip_y + draw_h) > src_h) {
		lv_disp_flush_ready(disp);
		return;
	}

	// 行基指针：不修改传入的 color_p，本地按行列计算偏移
	const lv_color_t* base_ptr = color_p;

	display_obj.tft.startWrite();
	display_obj.tft.setAddrWindow(flush_area.x1, flush_area.y1, draw_w, draw_h);

	for (int y = 0; y < draw_h; y++) {
		const lv_color_t* row_ptr = base_ptr + (skip_y + y) * src_w + skip_x;
		for (int x = 0; x < draw_w; x++) {
			display_obj.tft.writeColor(row_ptr[x].full, 1);
		}
	}

	display_obj.tft.endWrite();
	lv_disp_flush_ready(disp);
}

  
  bool my_touchpad_read(lv_indev_drv_t * indev_driver, lv_indev_data_t * data)
  {
    extern Display display_obj;
    
    uint16_t touchX, touchY;
  
    bool touched = display_obj.tft.getTouch(&touchX, &touchY, 600);
  
    if(!touched)
    {
      return false;
    }
  
    // if(touchX>WIDTH_1 || touchY > HEIGHT_1)
	if(touchX>TFT_WIDTH || touchY > TFT_HEIGHT)
    {
      Serial.println("Y or y outside of expected parameters..");
      Serial.print("y:");
      Serial.print(touchX);
      Serial.print(" x:");
      Serial.print(touchY);
    }
    else
    {
  
      data->state = touched ? LV_INDEV_STATE_PR : LV_INDEV_STATE_REL; 
       
      data->point.x = touchX;
      data->point.y = touchY;
  
    }
  
    return false;
  }
  
  void MenuFunctions::initLVGL() {
    tick.attach_ms(LVGL_TICK_PERIOD, lv_tick_handler);
    
    lv_init();
  
    lv_disp_buf_init(&disp_buf, buf, NULL, LV_HOR_RES_MAX * 10);
  
    lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    // disp_drv.hor_res = WIDTH_1;
    // disp_drv.ver_res = HEIGHT_1;
	disp_drv.hor_res = 240;
    disp_drv.ver_res = 320;
    disp_drv.flush_cb = my_disp_flush;
    disp_drv.buffer = &disp_buf;
    lv_disp_drv_register(&disp_drv);
  
    lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);             
    indev_drv.type = LV_INDEV_TYPE_POINTER;    
    indev_drv.read_cb = my_touchpad_read;      
    lv_indev_drv_register(&indev_drv);         
  }
  
  
  void MenuFunctions::deinitLVGL() {
    Serial.println(F("Deinit LVGL"));
    //lv_deinit();
  }
  
  
  // Event handler for settings drop down menus
  void setting_dropdown_cb(lv_obj_t * obj, lv_event_t event) {

  }

  // GFX Function to build a list showing all Stations scanned
  void MenuFunctions::addStationGFX(){
    extern LinkedList<Station>* stations;
    extern LinkedList<AccessPoint>* access_points;
    extern WiFiBleScan wifi_ble_scan_obj;
  
    lv_obj_t * list1 = lv_list_create(lv_scr_act(), NULL);
    lv_obj_set_size(list1, 160, 200);
    lv_obj_set_width(list1, LV_HOR_RES);
    lv_obj_align(list1, NULL, LV_ALIGN_CENTER, 0, 0);
  
    lv_obj_t * list_btn;
  
    lv_obj_t * label;
  
    list_btn = lv_list_add_btn(list1, LV_SYMBOL_CLOSE, text09);
    lv_obj_set_event_cb(list_btn, station_list_cb);

    char addr[] = "00:00:00:00:00:00";
    for (int x = 0; x < access_points->size(); x++) {
      AccessPoint cur_ap = access_points->get(x);

      // Add non clickable button for AP
      String full_label = "AP: " + cur_ap.essid;
      char buf[full_label.length() + 1] = {};
      full_label.toCharArray(buf, full_label.length() + 1);
      list_btn = lv_list_add_btn(list1, NULL, buf);
      lv_btn_set_checkable(list_btn, false);
      
      int cur_ap_sta_len = access_points->get(x).stations->size();
      for (int y = 0; y < cur_ap_sta_len; y++) {
        Station cur_sta = stations->get(cur_ap.stations->get(y));
        // Convert uint8_t MAC to char array
        wifi_ble_scan_obj.getMAC(addr, cur_sta.mac, 0);
        
        list_btn = lv_list_add_btn(list1, LV_SYMBOL_WIFI, addr);
        lv_btn_set_checkable(list_btn, true);
        lv_obj_set_event_cb(list_btn, station_list_cb);
    
        if (cur_sta.selected)
          lv_btn_toggle(list_btn);
      }
    }
  }

  // Function to work with list of Stations
  void station_list_cb(lv_obj_t * btn, lv_event_t event) {
    extern LinkedList<Station>* stations;
    extern MenuFunctions menu_function_obj;
    extern WiFiBleScan wifi_ble_scan_obj;
  
    String btn_text = lv_list_get_btn_text(btn);
    String display_string = "";
    char addr[] = "00:00:00:00:00:00";
    
    if (event == LV_EVENT_CLICKED) {
      if (btn_text != text09) {
      }
      else {
        Serial.println("Exiting...");
        lv_obj_del_async(lv_obj_get_parent(lv_obj_get_parent(btn)));
  
        for (int i = 0; i < stations->size(); i++) {
          if (stations->get(i).selected) {
            wifi_ble_scan_obj.getMAC(addr, stations->get(i).mac, 0);
            Serial.print("Selected: ");
            Serial.println(addr);
          }
        }
  
        printf("LV_EVENT_CANCEL\n");
        menu_function_obj.deinitLVGL();
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
        display_obj.exit_draw = true; // set everything back to normal
      }
    }
    
    if (event == LV_EVENT_VALUE_CHANGED) {     
      if (lv_btn_get_state(btn) == LV_BTN_STATE_CHECKED_RELEASED) {
        for (int i = 0; i < stations->size(); i++) {
          wifi_ble_scan_obj.getMAC(addr, stations->get(i).mac, 0); 
          if (strcmp(addr, btn_text.c_str()) == 0) {
            Serial.print("Adding Station: ");
            Serial.println(addr);
            Station sta = stations->get(i);
            sta.selected = true;
            stations->set(i, sta);
          }
        }
      }
      else {
        for (int i = 0; i < stations->size(); i++) {
          wifi_ble_scan_obj.getMAC(addr, stations->get(i).mac, 0); 
          if (strcmp(addr, btn_text.c_str()) == 0) {
            Serial.print("Removing Station: ");
            Serial.println(addr);
            Station sta = stations->get(i);
            sta.selected = false;
            stations->set(i, sta);
          }
        }
      }
    }
  }

  // GFX Function to build a list showing all APs scanned
void MenuFunctions::addAPGFX(String type)
{
	extern WiFiBleScan wifi_ble_scan_obj;
	extern LinkedList<AccessPoint>* access_points;
	extern LinkedList<AirTag>* airtags;
	
	// 清空之前的页面
	if (button_container) 
	{
		lv_obj_del(button_container);
		button_container = NULL;
	}
	for (int i = 0; i < BUTTON_ARRAY_LEN; i++) 
		lv_buttons[i] = NULL;

	// display_obj.clearScreen();
	// 清空当前页面
	lv_obj_clean(lv_scr_act());
	
	if(list1)
	{
		lv_obj_del(list1);
		list1 = NULL;
	}

	// 创建这个页面
    list1 = lv_list_create(lv_scr_act(), NULL);

	// lv_obj_set_style_local_bg_color(list1,LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_RED);
	lv_obj_set_style_local_radius(list1, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);
	lv_obj_set_style_local_border_width(list1, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);
	lv_obj_set_style_local_pad_inner(list1, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);

    lv_obj_set_size(list1, 320, 240);
    lv_obj_set_pos(list1,0,0);
	// lv_obj_t * btn = lv_list_add_btn(list1, LV_SYMBOL_OK, "testbtn");
	
	// Serial.printf("[addAPGFX] scr x:%d y:%d w:%d h:%d\n",
    //   lv_obj_get_x(lv_scr_act()), lv_obj_get_y(lv_scr_act()),
    //   lv_obj_get_width(lv_scr_act()), lv_obj_get_height(lv_scr_act()));

	// Serial.printf("list1 x:%d y:%d w:%d h:%d\n", lv_obj_get_x(list1), lv_obj_get_y(list1), lv_obj_get_width(list1), lv_obj_get_height(list1));

	// 这里默认进入渲染
	// 目前渲染逻辑有点奇怪
	// if(1)
	// {
	// 	g_block_lvgl = false;
	// 	g_limit_to_container = false;
	// 	// lv_obj_get_coords(list1, &g_btn_cont_area);
	// 	return;
	// }
    // lv_obj_set_size(list1, 160, 200);
	
	lv_obj_align(list1, NULL, LV_ALIGN_CENTER, 0, 0);

	g_block_lvgl = false;
	g_limit_to_container = false;
  
    lv_obj_t * list_btn;
  
    lv_obj_t * label;
  
    list_btn = lv_list_add_btn(list1, LV_SYMBOL_CLOSE, text09);
    lv_obj_set_event_cb(list_btn, ap_list_cb);
  
    if (type == "AP") {
      for (int i = 0; i < access_points->size(); i++) {
        char buf[access_points->get(i).essid.length() + 1] = {};
        access_points->get(i).essid.toCharArray(buf, access_points->get(i).essid.length() + 1);
        
        list_btn = lv_list_add_btn(list1, LV_SYMBOL_WIFI, buf);
        lv_btn_set_checkable(list_btn, true);
        lv_obj_set_event_cb(list_btn, ap_list_cb);
    
        if (access_points->get(i).selected)
          lv_btn_toggle(list_btn);
      }
    }
    else if (type == "Airtag") {
      for (int i = 0; i < airtags->size(); i++)
	  {
        char buf[airtags->get(i).mac.length() + 1] = {};
        airtags->get(i).mac.toCharArray(buf, airtags->get(i).mac.length() + 1);
        
        list_btn = lv_list_add_btn(list1, LV_SYMBOL_BLUETOOTH, buf);
        lv_btn_set_checkable(list_btn, true);
        lv_obj_set_event_cb(list_btn, at_list_cb);
    
        //if (airtags->get(i).selected)
        //  lv_btn_toggle(list_btn);
      }
    }
}
  
  void at_list_cb(lv_obj_t * btn, lv_event_t event) {
    extern MenuFunctions menu_function_obj;
    extern WiFiBleScan wifi_ble_scan_obj;
    extern LinkedList<AirTag>* airtags;
    extern Display display_obj;
  
    String btn_text = lv_list_get_btn_text(btn);
    String display_string = "";
    
    // Button is clicked
    if (event == LV_EVENT_CLICKED) {
      if (btn_text != text09) {
      }
      // It's the back button
      else {
        Serial.println("Exiting...");
        lv_obj_del_async(lv_obj_get_parent(lv_obj_get_parent(btn)));
  
        for (int i = 0; i < airtags->size(); i++) {
          if (airtags->get(i).selected) {
            Serial.println("Selected: " + (String)airtags->get(i).mac);
          }
        }
  
        printf("LV_EVENT_CANCEL\n");
        menu_function_obj.deinitLVGL();
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
        display_obj.exit_draw = true; // set everything back to normal
      }
    }
    
    if (event == LV_EVENT_VALUE_CHANGED) {      
      if (lv_btn_get_state(btn) == LV_BTN_STATE_CHECKED_RELEASED) {
        bool do_that_thang = false;
        for (int i = 0; i < airtags->size(); i++) {
          if (airtags->get(i).mac == btn_text) {
            Serial.println("Selecting Airtag: " + (String)airtags->get(i).mac);
            AirTag at = airtags->get(i);
            at.selected = true;
            airtags->set(i, at);
            do_that_thang = true;
          }
          else {
            AirTag at = airtags->get(i);
            at.selected = false;
            airtags->set(i, at);
          }
        }
        // Start spoofing airtag
        /*if (do_that_thang) {
          menu_function_obj.deinitLVGL();
          lv_obj_del_async(lv_obj_get_parent(lv_obj_get_parent(btn)));
          wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
          display_obj.clearScreen();
          menu_function_obj.orientDisplay();
          display_obj.clearScreen();
          menu_function_obj.drawStatusBar();
          wifi_ble_scan_obj.StartScan(BT_SPOOF_AIRTAG, TFT_WHITE);
        }*/
      }
      else {
        for (int i = 0; i < airtags->size(); i++) {
          if (airtags->get(i).mac == btn_text) {
            Serial.println("Deselecting Airtag: " + (String)airtags->get(i).mac);
            AirTag at = airtags->get(i);
            at.selected = false;
            airtags->set(i, at);
          }
        }
      }
    }
  }
  
  void ap_list_cb(lv_obj_t * btn, lv_event_t event) {
    extern LinkedList<AccessPoint>* access_points;
    extern MenuFunctions menu_function_obj;
    extern WiFiBleScan wifi_ble_scan_obj;
  
    String btn_text = lv_list_get_btn_text(btn);
    String display_string = "";
    
    if (event == LV_EVENT_CLICKED) {
      if (btn_text != text09) {

      }
      else 
	  {
        Serial.println("Exiting...");
		// async会有bug
        // lv_obj_del_async(lv_obj_get_parent(lv_obj_get_parent(btn)));

		lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(btn)));
  
        for (int i = 0; i < access_points->size(); i++) {
          if (access_points->get(i).selected) {
            Serial.println("Selected: " + (String)access_points->get(i).essid);
          }
        }
  
        printf("LV_EVENT_CANCEL\n");
        menu_function_obj.deinitLVGL();
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
        display_obj.exit_draw = true; // set everything back to normal
      }
    }
    
    if (event == LV_EVENT_VALUE_CHANGED) {      
      if (lv_btn_get_state(btn) == LV_BTN_STATE_CHECKED_RELEASED) {
        for (int i = 0; i < access_points->size(); i++) {
          if (access_points->get(i).essid == btn_text) {
            Serial.println("Adding AP: " + (String)access_points->get(i).essid);
            AccessPoint ap = access_points->get(i);
            ap.selected = true;
            access_points->set(i, ap);
          }
        }
      }
      else {
        for (int i = 0; i < access_points->size(); i++) {
          if (access_points->get(i).essid == btn_text) {
            Serial.println("Removing AP: " + (String)access_points->get(i).essid);
            AccessPoint ap = access_points->get(i);
            ap.selected = false;
            access_points->set(i, ap);
          }
        }
      }
    }
  }
  
  void MenuFunctions::addSSIDGFX(){
    extern LinkedList<ssid>* ssids;
    
    String display_string = "";
    // Create a keyboard and apply the styles
    kb = lv_keyboard_create(lv_scr_act(), NULL);
    lv_obj_set_size(kb, LV_HOR_RES, LV_VER_RES / 2);
    lv_obj_set_event_cb(kb, add_ssid_keyboard_event_cb);
  
    // Create one text area
    // Store all SSIDs
    ta1 = lv_textarea_create(lv_scr_act(), NULL);
    lv_textarea_set_one_line(ta1, false);
    lv_obj_set_width(ta1, LV_HOR_RES);
    lv_obj_set_height(ta1, (LV_VER_RES / 2) - 35);
    lv_obj_set_pos(ta1, 5, 20);
    lv_textarea_set_cursor_hidden(ta1, true);
    lv_obj_align(ta1, NULL, LV_ALIGN_IN_TOP_MID, NULL, NULL);
    lv_textarea_set_placeholder_text(ta1, text_table1[0]);
  
    // Create second text area
    // Add SSIDs
    ta2 = lv_textarea_create(lv_scr_act(), ta1);
    lv_textarea_set_cursor_hidden(ta2, false);
    lv_textarea_set_one_line(ta2, true);
    lv_obj_align(ta2, NULL, LV_ALIGN_IN_TOP_MID, NULL, (LV_VER_RES / 2) - 35);
    lv_textarea_set_text(ta2, "");
    lv_textarea_set_placeholder_text(ta2, text_table1[1]);
  
    // After generating text areas, add text to first text box
    for (int i = 0; i < ssids->size(); i++)
      display_string.concat((String)ssids->get(i).essid + "\n");
      
    lv_textarea_set_text(ta1, display_string.c_str());
  
    // Focus it on one of the text areas to start
    lv_keyboard_set_textarea(kb, ta2);
    lv_keyboard_set_cursor_manage(kb, true);
    
  }
  
  // Keyboard callback dedicated to joining wifi
  void add_ssid_keyboard_event_cb(lv_obj_t * keyboard, lv_event_t event){
    extern Display display_obj;
    extern MenuFunctions menu_function_obj;
    extern WiFiBleScan wifi_ble_scan_obj;
    extern LinkedList<ssid>* ssids;
    
    lv_keyboard_def_event_cb(kb, event);
  
    // User has applied text box
    if(event == LV_EVENT_APPLY){
      String display_string = "";
      printf("LV_EVENT_APPLY\n");
  
      // Get text from SSID text box
      String ta2_text = lv_textarea_get_text(ta2);
      Serial.println(ta2_text);
  
      // Add text box text to list of SSIDs
      wifi_ble_scan_obj.addSSID(ta2_text);
  
      // Update large text box with ssid
      for (int i = 0; i < ssids->size(); i++)
        display_string.concat((String)ssids->get(i).essid + "\n");
      lv_textarea_set_text(ta1, display_string.c_str());
  
      lv_textarea_set_text(ta2, "");
    }

	else if(event == LV_EVENT_CANCEL)
	{
    //   printf("LV_EVENT_CANCEL\n");
    //   menu_function_obj.deinitLVGL();

    	display_obj.exit_draw = true; // set everything back to normal
    }
  }
  
  
  void ta_event_cb(lv_obj_t * ta, lv_event_t event)
  {
    if(event == LV_EVENT_CLICKED) {
      if(kb != NULL)
        lv_keyboard_set_textarea(kb, ta);
    }
  
  }

#endif
//// END LV_ARDUINO STUFF

void MenuFunctions::buttonNotSelected(uint8_t b, int8_t x) {
  if (x == -1)
    x = b;

  #ifdef HAS_MINI_SCREEN
    display_obj.tft.setFreeFont(NULL);
    display_obj.key[b].drawButton(false, current_menu->list->get(x).name);
  #endif

  #ifdef HAS_FULL_SCREEN
    display_obj.tft.setFreeFont(MENU_FONT);
    display_obj.key[b].drawButton(false, current_menu->list->get(x).name);
    if ((current_menu->list->get(x).name != text09) && (current_menu->list->get(x).icon != 255))
          display_obj.tft.drawXBitmap(0,
                                      KEY_Y + x * (KEY_H + KEY_SPACING_Y) - (ICON_H / 2),
                                      menu_icons[current_menu->list->get(x).icon],
                                      ICON_W,
                                      ICON_H,
                                      TFT_BLACK,
                                      current_menu->list->get(x).color);
    display_obj.tft.setFreeFont(NULL);
  #endif
}

void MenuFunctions::buttonSelected(uint8_t b, int8_t x) {
  #ifndef HAS_ILI9341
    if (x == -1)
      x = b;

    #ifdef HAS_MINI_SCREEN
      display_obj.tft.setFreeFont(NULL);
      display_obj.key[b].drawButton(true, current_menu->list->get(x).name);
    #endif

    #ifdef HAS_FULL_SCREEN
      display_obj.tft.setFreeFont(MENU_FONT);
      display_obj.key[b].drawButton(true, current_menu->list->get(x).name);
      if ((current_menu->list->get(x).name != text09) && (current_menu->list->get(x).icon != 255))
            display_obj.tft.drawXBitmap(0,
                                        KEY_Y + x * (KEY_H + KEY_SPACING_Y) - (ICON_H / 2),
                                        menu_icons[current_menu->list->get(x).icon],
                                        ICON_W,
                                        ICON_H,
                                        TFT_BLACK,
                                        current_menu->list->get(x).color);
      display_obj.tft.setFreeFont(NULL);
    #endif
  #endif
}

// Function to check menu input
void MenuFunctions::main(uint32_t currentTime)
{
  	// Some function exited and we need to go back to normal
	if (display_obj.exit_draw) 
	{

		wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
		display_obj.exit_draw = false;
		this->orientDisplay();

	}
	if ((wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_OFF) ||
		(wifi_ble_scan_obj.currentScanMode == OTA_UPDATE) ||
		(wifi_ble_scan_obj.currentScanMode == ESP_UPDATE) ||
		(wifi_ble_scan_obj.currentScanMode == SHOW_INFO) ||
		(wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_GPS_DATA) ||
		(wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_GPS_NMEA)) 
	{
		if (wifi_ble_scan_obj.orient_display) 
		{
			this->orientDisplay();
			wifi_ble_scan_obj.orient_display = false;
		}
  	}

	if (currentTime != 0) 
	{
		if (currentTime - initTime >= BANNER_TIME) 
		{
			this->initTime = millis();
			if ((wifi_ble_scan_obj.currentScanMode != LV_JOIN_WIFI) &&
				(wifi_ble_scan_obj.currentScanMode != LV_ADD_SSID))
			this->updateStatusBar();
		}
	}


	boolean pressed = false;
	// This is code from bodmer's keypad example
	uint16_t t_x = 0, t_y = 0; // To store the touch coordinates

	// Get the display buffer out of the way
	if ((wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_OFF ))
		display_obj.displayBuffer();


  // Pressed will be set true is there is a valid touch on the screen
	int pre_getTouch = millis();

	// getTouch causes a 10ms delay which makes beacon spam less effective
	#ifdef HAS_ILI9341
	if (!this->disable_touch)
		pressed = this->updateTouch(&t_x, &t_y);
	#endif


  // This is if there are scans/attacks going on
  #ifdef HAS_ILI9341
    if ((wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_OFF) &&
        (pressed) &&
        (wifi_ble_scan_obj.currentScanMode != OTA_UPDATE) &&
        (wifi_ble_scan_obj.currentScanMode != ESP_UPDATE) &&
        (wifi_ble_scan_obj.currentScanMode != SHOW_INFO) &&
        (wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_GPS_DATA) &&
        (wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_GPS_NMEA))
    {
      // Stop the current scan
      if ((wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_PROBE) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_RAW_CAPTURE) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_STATION) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_AP) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_SIG_STREN) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_TARGET_AP) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_TARGET_AP_FULL) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_ESPRESSIF) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_ALL) ||
          (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_DEAUTH) ||
          (wifi_ble_scan_obj.currentScanMode == BT_SCAN_ALL) ||
          (wifi_ble_scan_obj.currentScanMode == BT_SCAN_AIRTAG) ||
          (wifi_ble_scan_obj.currentScanMode == BT_SCAN_FLIPPER))
      {
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
  
        // If we don't do this, the text and button coordinates will be off
        display_obj.tft.init();
  
        // Take us back to the menu
        changeMenu(current_menu);
      }
  
      x = -1;
      y = -1;
  
      return;
    }
  #endif

  #ifdef HAS_BUTTONS

    bool c_btn_press = c_btn.justPressed();

    #ifndef HAS_ILI9341
    
      if ((c_btn_press) &&
          (wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_OFF) &&
          (wifi_ble_scan_obj.currentScanMode != OTA_UPDATE) &&
          (wifi_ble_scan_obj.currentScanMode != ESP_UPDATE) &&
          (wifi_ble_scan_obj.currentScanMode != SHOW_INFO) &&
          (wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_GPS_DATA) &&
          (wifi_ble_scan_obj.currentScanMode != WIFI_SCAN_GPS_NMEA))
      {
        // Stop the current scan
        if ((wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_PROBE) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_RAW_CAPTURE) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_STATION) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_AP) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_SIG_STREN) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_TARGET_AP) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_TARGET_AP_FULL) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_ESPRESSIF) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_ALL) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_SCAN_DEAUTH) ||
            (wifi_ble_scan_obj.currentScanMode == BT_SCAN_ALL) ||
            (wifi_ble_scan_obj.currentScanMode == BT_SCAN_AIRTAG) ||
            (wifi_ble_scan_obj.currentScanMode == BT_SCAN_FLIPPER) ||
            (wifi_ble_scan_obj.currentScanMode == WIFI_PACKET_MONITOR))
        {
          wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
    
          // If we don't do this, the text and button coordinates will be off
          display_obj.tft.init();
    
          // Take us back to the menu
          changeMenu(current_menu);
        }
    
        x = -1;
        y = -1;
    
        return;
      }
    #endif

  #endif


  // Check if any key coordinate boxes contain the touch coordinates
  // This is for when on a menu
  #ifdef HAS_ILI9341
      // Need this to set all keys to false
      for (uint8_t b = 0; b < BUTTON_ARRAY_LEN; b++) {
        if (pressed && display_obj.key[b].contains(t_x, t_y)) {
          display_obj.key[b].press(true);  // tell the button it is pressed
        } else {
          display_obj.key[b].press(false);  // tell the button it is NOT pressed
        }
      }
  
      // Check if any key has changed state
      for (uint8_t b = 0; b < current_menu->list->size(); b++) {
        display_obj.tft.setFreeFont(MENU_FONT);
        if (display_obj.key[b].justPressed()) {
          display_obj.key[b].drawButton(true, current_menu->list->get(b).name);
          if (current_menu->list->get(b).name != text09)
            display_obj.tft.drawXBitmap(0,
                                        KEY_Y + b * (KEY_H + KEY_SPACING_Y) - (ICON_H / 2),
                                        menu_icons[current_menu->list->get(b).icon],
                                        ICON_W,
                                        ICON_H,
                                        current_menu->list->get(b).color,
                                        TFT_BLACK);
        }
  
        // If button was just release, execute the button's function
        if ((display_obj.key[b].justReleased()) && (!pressed))
        {
          display_obj.key[b].drawButton(false, current_menu->list->get(b).name);
          current_menu->list->get(b).callable();
        }
        // This
        else if ((display_obj.key[b].justReleased()) && (pressed)) {
          display_obj.key[b].drawButton(false, current_menu->list->get(b).name);
          if (current_menu->list->get(b).name != text09)
            display_obj.tft.drawXBitmap(0,
                                        KEY_Y + b * (KEY_H + KEY_SPACING_Y) - (ICON_H / 2),
                                        menu_icons[current_menu->list->get(b).icon],
                                        ICON_W,
                                        ICON_H,
                                        TFT_BLACK,
                                        current_menu->list->get(b).color);
        }
  
        display_obj.tft.setFreeFont(NULL);
      }
    
    x = -1;
    y = -1;
  #endif

}

void MenuFunctions::battery(bool initial)
{
  #ifdef HAS_BATTERY
    uint16_t the_color;

    if (battery_obj.i2c_supported)
    {

      // Could use int compare maybe idk
      if (((String)battery_obj.battery_level != "25") && ((String)battery_obj.battery_level != "0"))
        the_color = TFT_GREEN;
      else
        the_color = TFT_RED;

      if ((battery_obj.battery_level != battery_obj.old_level) || (initial)) {
        battery_obj.old_level = battery_obj.battery_level;
        display_obj.tft.fillRect(204, 0, SCREEN_WIDTH, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
      }

      display_obj.tft.setCursor(0, 1);
      display_obj.tft.drawString((String)battery_obj.battery_level + "%", 204, 0, 2);  // without real info, it's -1% now

    }
  #endif
}
void MenuFunctions::battery2(bool initial)
{
  MenuFunctions::battery(initial);
}
//#endif

void MenuFunctions::updateStatusBar()
{
  display_obj.tft.setTextSize(1);

  bool status_changed = false;
  
  uint16_t the_color; 

  if (this->old_gps_sat_count != gps_obj.getNumSats()) {
    this->old_gps_sat_count = gps_obj.getNumSats();
    display_obj.tft.fillRect(0, 0, 240, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
    status_changed = true;
  }

  // GPS Stuff
  #ifdef HAS_GPS
    if (gps_obj.getGpsModuleStatus()) {
      if (gps_obj.getFixStatus())
        the_color = TFT_GREEN;
      else
        the_color = TFT_RED;
        
      #ifdef HAS_FULL_SCREEN
        display_obj.tft.drawXBitmap(4,
                                    0,
                                    menu_icons[STATUS_GPS],
                                    16,
                                    16,
                                    STATUSBAR_COLOR,
                                    the_color);
        display_obj.tft.setTextColor(TFT_WHITE, STATUSBAR_COLOR);

        display_obj.tft.drawString(gps_obj.getNumSatsString(), 22, 0, 2);
      #elif defined(HAS_SCREEN)
        display_obj.tft.setTextColor(the_color, STATUSBAR_COLOR);
        display_obj.tft.drawString("GPS", 0, 0, 1);
      #endif
    }
  #endif

  display_obj.tft.setTextColor(TFT_WHITE, STATUSBAR_COLOR);

  // WiFi Channel Stuff
  if ((wifi_ble_scan_obj.set_channel != wifi_ble_scan_obj.old_channel) || (status_changed)) {
    wifi_ble_scan_obj.old_channel = wifi_ble_scan_obj.set_channel;

    display_obj.tft.fillRect(50, 0, TFT_WIDTH * 0.21, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.drawString("CH: " + (String)wifi_ble_scan_obj.set_channel, 50, 0, 2);
    #endif

    #ifdef HAS_MINI_SCREEN
      display_obj.tft.drawString("CH: " + (String)wifi_ble_scan_obj.set_channel, TFT_WIDTH/4, 0, 1);
    #endif
  }

  // RAM Stuff
  wifi_ble_scan_obj.freeRAM();
  if ((wifi_ble_scan_obj.free_ram != wifi_ble_scan_obj.old_free_ram) || (status_changed)) {
    wifi_ble_scan_obj.old_free_ram = wifi_ble_scan_obj.free_ram;
    display_obj.tft.fillRect(100, 0, 60, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
    #ifdef HAS_FULL_SCREEN
      display_obj.tft.drawString((String)wifi_ble_scan_obj.free_ram + "B", 100, 0, 2);
    #endif

    #ifdef HAS_MINI_SCREEN
      display_obj.tft.drawString((String)wifi_ble_scan_obj.free_ram + "B", TFT_WIDTH/1.75, 0, 1);
    #endif
  }

  // Draw battery info
  MenuFunctions::battery(false);
  display_obj.tft.fillRect(186, 0, 16, STATUS_BAR_WIDTH, STATUSBAR_COLOR);

  
  #ifdef HAS_ILI9341
    #ifdef HAS_BUTTONS
      if (this->disable_touch) {
        display_obj.tft.setCursor(0, 1);
        display_obj.tft.drawXBitmap(186,
                                    0,
                                    menu_icons[DISABLE_TOUCH],
                                    16,
                                    16,
                                    STATUSBAR_COLOR,
                                    TFT_RED);
      }
    #endif
  #endif


  // Draw SD info
  #ifdef HAS_SD
    if (sd_obj.supported)
      the_color = TFT_GREEN;
    else
      the_color = TFT_RED;

    #ifdef HAS_FULL_SCREEN
      display_obj.tft.drawXBitmap(170,
                                  0,
                                  menu_icons[STATUS_SD],
                                  16,
                                  16,
                                  STATUSBAR_COLOR,
                                  the_color);
    #endif
  #endif

  #ifdef HAS_MINI_SCREEN
    display_obj.tft.setTextColor(the_color, STATUSBAR_COLOR);
    display_obj.tft.drawString("SD", TFT_WIDTH - 12, 0, 1);
  #endif
}

void MenuFunctions::drawStatusBar()
{
  display_obj.tft.setTextSize(1);
  #ifdef HAS_MINI_SCREEN
    display_obj.tft.setFreeFont(NULL);
  #endif
  display_obj.tft.fillRect(0, 0, 240, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
  display_obj.tft.setTextColor(TFT_WHITE, STATUSBAR_COLOR);

  uint16_t the_color;

  // GPS Stuff
  #ifdef HAS_GPS
    if (gps_obj.getGpsModuleStatus()) {
      if (gps_obj.getFixStatus())
        the_color = TFT_GREEN;
      else
        the_color = TFT_RED;
        
      #ifdef HAS_FULL_SCREEN
        display_obj.tft.drawXBitmap(4,
                                    0,
                                    menu_icons[STATUS_GPS],
                                    16,
                                    16,
                                    STATUSBAR_COLOR,
                                    the_color);
        display_obj.tft.setTextColor(TFT_WHITE, STATUSBAR_COLOR);

        display_obj.tft.drawString(gps_obj.getNumSatsString(), 22, 0, 2);
      #endif
    }
  #endif

  display_obj.tft.setTextColor(TFT_WHITE, STATUSBAR_COLOR);


  // WiFi Channel Stuff
  wifi_ble_scan_obj.old_channel = wifi_ble_scan_obj.set_channel;
  #ifdef HAS_MINI_SCREEN
    display_obj.tft.fillRect(43, 0, TFT_WIDTH * 0.21, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
  #else
    display_obj.tft.fillRect(50, 0, TFT_WIDTH * 0.21, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
  #endif
  #ifdef HAS_FULL_SCREEN
    display_obj.tft.drawString("CH: " + (String)wifi_ble_scan_obj.set_channel, 50, 0, 2);
  #endif

  #ifdef HAS_MINI_SCREEN
    display_obj.tft.drawString("CH: " + (String)wifi_ble_scan_obj.set_channel, TFT_WIDTH/4, 0, 1);
  #endif

  // RAM Stuff
  wifi_ble_scan_obj.freeRAM();
  wifi_ble_scan_obj.old_free_ram = wifi_ble_scan_obj.free_ram;
  display_obj.tft.fillRect(100, 0, 60, STATUS_BAR_WIDTH, STATUSBAR_COLOR);
  #ifdef HAS_FULL_SCREEN
    display_obj.tft.drawString((String)wifi_ble_scan_obj.free_ram + "B", 100, 0, 2);
  #endif

  #ifdef HAS_MINI_SCREEN
    display_obj.tft.drawString((String)wifi_ble_scan_obj.free_ram + "B", TFT_WIDTH/1.75, 0, 1);
  #endif


  MenuFunctions::battery(true);
  display_obj.tft.fillRect(186, 0, 16, STATUS_BAR_WIDTH, STATUSBAR_COLOR);


  #ifdef HAS_ILI9341
    #ifdef HAS_BUTTONS
      if (this->disable_touch) {
        display_obj.tft.setCursor(0, 1);
        display_obj.tft.drawXBitmap(186,
                                    0,
                                    menu_icons[DISABLE_TOUCH],
                                    16,
                                    16,
                                    STATUSBAR_COLOR,
                                    TFT_RED);
      }
    #endif
  #endif

  // Draw SD info
  #ifdef HAS_SD
    if (sd_obj.supported)
      the_color = TFT_GREEN;
    else
      the_color = TFT_RED;
  

    #ifdef HAS_FULL_SCREEN
      display_obj.tft.drawXBitmap(170,
                                  0,
                                  menu_icons[STATUS_SD],
                                  16,
                                  16,
                                  STATUSBAR_COLOR,
                                  the_color);
    #endif
  #endif

  #ifdef HAS_MINI_SCREEN
    display_obj.tft.setTextColor(the_color, STATUSBAR_COLOR);
    display_obj.tft.drawString("SD", TFT_WIDTH - 12, 0, 1);
  #endif
}

void MenuFunctions::orientDisplay()
{
  display_obj.tft.init();

  display_obj.tft.setRotation(0); // Portrait

  display_obj.tft.setCursor(0, 0);

  #ifdef HAS_ILI9341
    #ifdef TFT_SHIELD
      uint16_t calData[5] = { 275, 3494, 361, 3528, 4 }; // tft.setRotation(0); // Portrait with TFT Shield
    #else if defined(TFT_DIY)   // this is to set direction after exit of packet monitor
      uint16_t calData[5] = { 339, 3470, 237, 3438, 2 }; // default touch
      //uint16_t calData[5] = { 339, 3470, 237, 3438, 4 }; // inverted touch by s 
      display_obj.tft.setRotation(0); // Portrait with DIY TFT default re-enter menu direction from packet monitor
    #endif

    display_obj.tft.setTouch(calData);
  #endif

  changeMenu(current_menu);
}

void MenuFunctions::runBoolSetting(String key) {
  display_obj.tftDrawRedOnOffButton();
}

String MenuFunctions::callSetting(String key) {
  specSettingMenu.name = key;
  
  String setting_type = settings_obj.getSettingType(key);

  if (setting_type == "bool") {
    return "bool";
  }
}

void MenuFunctions::displaySetting(String key, Menu* menu, int index) {
  int good_offset = 150;
  specSettingMenu.name = key;
	
  bool setting_value = settings_obj.loadSetting<bool>(key);

  // Make a local copy of menu node
  MenuNode node = menu->list->get(index);

  display_obj.tft.setTextWrap(false);
  display_obj.tft.setFreeFont(NULL);
  display_obj.tft.setCursor(0, good_offset);
  display_obj.tft.setTextSize(1);

  // Set local copy value
  if (!setting_value) {
    display_obj.tft.setTextColor(TFT_RED);
    display_obj.tft.println(F(text_table1[4]));
    node.selected = false;
  }
  else {
    display_obj.tft.setTextColor(TFT_GREEN);
    display_obj.tft.println(F(text_table1[5]));
    node.selected = true;
  }

  // Put local copy back into menu
  menu->list->set(index, node);
    
}

// Function to build the menus
void MenuFunctions::RunSetup()
{
  extern LinkedList<AccessPoint>* access_points;
  extern LinkedList<Station>* stations;
  extern LinkedList<AirTag>* airtags;

  this->disable_touch = false;
  
  #ifdef HAS_ILI9341
    // this->initLVGL();
  #endif
   
  // root menu stuff
  mainMenu.list = new LinkedList<MenuNode>(); // Get list in first menu ready

  // Main menu stuff
  wifiMenu.list = new LinkedList<MenuNode>(); // Get list in second menu ready
  bluetoothMenu.list = new LinkedList<MenuNode>(); // Get list in third menu ready
  radioReceiverMenu.list = new LinkedList<MenuNode>(); 
  deviceMenu.list = new LinkedList<MenuNode>();
  #ifdef HAS_GPS
    if (gps_obj.getGpsModuleStatus()) {
      gpsInfoMenu.list = new LinkedList<MenuNode>();
    }
  #endif

  // Device menu stuff
  failedUpdateMenu.list = new LinkedList<MenuNode>();
  whichUpdateMenu.list = new LinkedList<MenuNode>();
  confirmMenu.list = new LinkedList<MenuNode>();
  updateMenu.list = new LinkedList<MenuNode>();
  settingsMenu.list = new LinkedList<MenuNode>();
  specSettingMenu.list = new LinkedList<MenuNode>();
  infoMenu.list = new LinkedList<MenuNode>();
  languageMenu.list = new LinkedList<MenuNode>();

  // WiFi menu stuff
  wifiSnifferMenu.list = new LinkedList<MenuNode>();
  wifiGeneralMenu.list = new LinkedList<MenuNode>();
  wifiAPMenu.list = new LinkedList<MenuNode>();
  #ifdef HAS_BT
    airtagMenu.list = new LinkedList<MenuNode>();
  #endif
  #ifndef HAS_ILI9341
    wifiStationMenu.list = new LinkedList<MenuNode>();
  #endif

  // WiFi HTML menu stuff
  htmlMenu.list = new LinkedList<MenuNode>();
  #if (!defined(HAS_ILI9341) && defined(HAS_BUTTONS))
    miniKbMenu.list = new LinkedList<MenuNode>();
  #endif
  #ifndef HAS_ILI9341
    #ifdef HAS_BUTTONS
      #ifdef HAS_SD
        sdDeleteMenu.list = new LinkedList<MenuNode>();
      #endif
    #endif
  #endif

  // Bluetooth menu stuff
  bluetoothSnifferMenu.list = new LinkedList<MenuNode>();
  //bluetoothAttackMenu.list = new LinkedList<MenuNode>();

  // Settings stuff
  generateSSIDsMenu.list = new LinkedList<MenuNode>();
  clearSSIDsMenu.list = new LinkedList<MenuNode>();
  clearAPsMenu.list = new LinkedList<MenuNode>();
  saveFileMenu.list = new LinkedList<MenuNode>();

  saveAPsMenu.list = new LinkedList<MenuNode>();
  loadAPsMenu.list = new LinkedList<MenuNode>();
  saveATsMenu.list = new LinkedList<MenuNode>();
  loadATsMenu.list = new LinkedList<MenuNode>();

  // Work menu names
  mainMenu.name = text_table1[6];
  wifiMenu.name = text_table1[7];
  radioReceiverMenu.name = "Radio Receiver";

  deviceMenu.name = text_table1[9];
  failedUpdateMenu.name = text_table1[11];
  whichUpdateMenu.name = text_table1[12];
  confirmMenu.name = text_table1[13];
  updateMenu.name = text_table1[15];
  languageMenu.name = text_table1[16]; 
  infoMenu.name = text_table1[17];
  settingsMenu.name = text_table1[18];
  bluetoothMenu.name = text_table1[19];
  wifiSnifferMenu.name = text_table1[20];
  wifiGeneralMenu.name = text_table1[22];
  saveFileMenu.name = "Save/Load Files";
  saveAPsMenu.name = "Save APs";
  loadAPsMenu.name = "Load APs";
  saveATsMenu.name = "Save Airtags";
  loadATsMenu.name = "Load Airtags";

  bluetoothSnifferMenu.name = text_table1[23];
  generateSSIDsMenu.name = text_table1[27];
  clearSSIDsMenu.name = text_table1[28];
  clearAPsMenu.name = text_table1[29];
  wifiAPMenu.name = "Access Points";
  #ifdef HAS_BT
    airtagMenu.name = "Select Airtag";
  #endif
  #ifndef HAS_ILI9341
    wifiStationMenu.name = "Select Stations";
  #endif
  #ifdef HAS_GPS
    gpsInfoMenu.name = "GPS Data";
  #endif  
  #if (!defined(HAS_ILI9341) && defined(HAS_BUTTONS))
    miniKbMenu.name = "Mini Keyboard";
  #endif
  #ifdef HAS_SD
    #ifndef HAS_ILI9341
      sdDeleteMenu.name = "Delete SD Files";
    #endif
  #endif

  // Build Main Menu
  mainMenu.parentMenu = NULL;
  this->addNodes(&mainMenu, text_table1[7], TFT_GREEN, NULL, WIFI, [this]() {
	
	
	this->changeMenu(&wifiMenu);
  });
  this->addNodes(&mainMenu, text_table1[19], TFT_CYAN, NULL, BLUETOOTH, [this]() {
    this->changeMenu(&bluetoothMenu);
  });
  this->addNodes(&mainMenu, "Radio Receiver", TFT_YELLOW, NULL, RADIO, [this]() {
     this->changeMenu(&radioReceiverMenu); //without this, menu will be strange
      radio_obj.change_screen();
  });
  this->addNodes(&mainMenu, text_table1[9], TFT_BLUE, NULL, DEVICE, [this]() {
    this->changeMenu(&deviceMenu);
  });
  this->addNodes(&mainMenu, text_table1[30], TFT_LIGHTGREY, NULL, REBOOT, []() {
    ESP.restart();
  });

  // Build Radio Receiver Menu
  radioReceiverMenu.parentMenu = &mainMenu;
  this->addNodes(&radioReceiverMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(radioReceiverMenu.parentMenu);
    radio_obj.stop_screen();
  });
 
  // Build WiFi Menu
  wifiMenu.parentMenu = &mainMenu; // Main Menu is second menu parent
  this->addNodes(&wifiMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(wifiMenu.parentMenu);
  });
  this->addNodes(&wifiMenu, text_table1[31], TFT_YELLOW, NULL, SNIFFERS, [this]() {
    this->changeMenu(&wifiSnifferMenu);
  });
  this->addNodes(&wifiMenu, text_table1[33], TFT_PURPLE, NULL, GENERAL_APPS, [this]() {
    this->changeMenu(&wifiGeneralMenu);
  });

  // Build WiFi sniffer Menu
  wifiSnifferMenu.parentMenu = &wifiMenu; // Main Menu is second menu parent
  this->addNodes(&wifiSnifferMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(wifiSnifferMenu.parentMenu);
  });

  this->addNodes(&wifiSnifferMenu, text_table1[42], TFT_CYAN, NULL, PROBE_SNIFF, [this]() {
    	
		hiden_LVGL_menu();
	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(WIFI_SCAN_PROBE, TFT_CYAN);
  });
  this->addNodes(&wifiSnifferMenu, text_table1[43], TFT_MAGENTA, NULL, BEACON_SNIFF, [this]() {
    	
		hiden_LVGL_menu();
	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(WIFI_SCAN_AP, TFT_MAGENTA);
  });
  #ifdef HAS_ILI9341
    this->addNodes(&wifiSnifferMenu, text_table1[45], TFT_BLUE, NULL, PACKET_MONITOR, [this]() {
    	hiden_LVGL_menu();
	  	wifi_ble_scan_obj.StartScan(WIFI_PACKET_MONITOR, TFT_BLUE);
    });
  #else
    this->addNodes(&wifiSnifferMenu, text_table1[45], TFT_BLUE, NULL, PACKET_MONITOR, [this]() {
      display_obj.clearScreen();
      this->drawStatusBar();
      wifi_ble_scan_obj.StartScan(WIFI_PACKET_MONITOR, TFT_BLUE);
    });
  #endif
  this->addNodes(&wifiSnifferMenu, text_table1[49], TFT_MAGENTA, NULL, BEACON_SNIFF, [this]() {

    hiden_LVGL_menu();

	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(WIFI_SCAN_TARGET_AP, TFT_MAGENTA);
  });
  this->addNodes(&wifiSnifferMenu, text_table1[58], TFT_WHITE, NULL, PACKET_MONITOR, [this]() {
    
	hiden_LVGL_menu();
	
	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(WIFI_SCAN_RAW_CAPTURE, TFT_WHITE);
  });
  this->addNodes(&wifiSnifferMenu, text_table1[59], TFT_ORANGE, NULL, PACKET_MONITOR, [this]() {
	
    hiden_LVGL_menu();

	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(WIFI_SCAN_STATION, TFT_WHITE);
  });
  #ifdef HAS_ILI9341
    this->addNodes(&wifiSnifferMenu, "Signal Monitor", TFT_CYAN, NULL, PACKET_MONITOR, [this]() {
    	
		hiden_LVGL_menu();
      
	  display_obj.clearScreen();
      this->drawStatusBar();
      wifi_ble_scan_obj.StartScan(WIFI_SCAN_SIG_STREN, TFT_CYAN);
    });
  #endif

  // Build WiFi General menu
  wifiGeneralMenu.parentMenu = &wifiMenu;
  this->addNodes(&wifiGeneralMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(wifiGeneralMenu.parentMenu);
  });

  #ifdef HAS_ILI9341
    // Select APs on OG
    this->addNodes(&wifiGeneralMenu, text_table1[56], TFT_NAVY, NULL, KEYBOARD_ICO, [this](){
      display_obj.clearScreen(); 
      wifi_ble_scan_obj.currentScanMode = LV_ADD_SSID; 
      wifi_ble_scan_obj.StartScan(LV_ADD_SSID, TFT_RED);  
      addAPGFX();
    });
  #endif

  // Build Bluetooth Menu
  bluetoothMenu.parentMenu = &mainMenu; // Second Menu is third menu parent
  this->addNodes(&bluetoothMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() 
  {
		// wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
		// reshow_LVGL_menu();
		this->changeMenu(bluetoothMenu.parentMenu);
  });

  this->addNodes(&bluetoothMenu, text_table1[31], TFT_YELLOW, NULL, SNIFFERS, [this]() {
    this->changeMenu(&bluetoothSnifferMenu);
  });

  // Build bluetooth sniffer Menu
  bluetoothSnifferMenu.parentMenu = &bluetoothMenu; // Second Menu is third menu parent
  //   exit按键？
  this->addNodes(&bluetoothSnifferMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() 
  {
	this->changeMenu(bluetoothSnifferMenu.parentMenu);
  });

  //   blue toothsniff
  this->addNodes(&bluetoothSnifferMenu, text_table1[34], TFT_GREEN, NULL, BLUETOOTH_SNIFF, [this]() 
  {
	hiden_LVGL_menu();
	display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(BT_SCAN_ALL, TFT_GREEN);
    
  });
  this->addNodes(&bluetoothSnifferMenu, "Flipper Sniff", TFT_ORANGE, NULL, FLIPPER, [this]() 
  {
	hiden_LVGL_menu();
    display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(BT_SCAN_FLIPPER, TFT_ORANGE);
  });
  this->addNodes(&bluetoothSnifferMenu, "Airtag Sniff", TFT_WHITE, NULL, BLUETOOTH_SNIFF, [this]() 
  {
	hiden_LVGL_menu();
    display_obj.clearScreen();
    this->drawStatusBar();
    wifi_ble_scan_obj.StartScan(BT_SCAN_AIRTAG, TFT_WHITE);
  });


  // Device menu
  deviceMenu.parentMenu = &mainMenu;
  this->addNodes(&deviceMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(deviceMenu.parentMenu);
  });
  this->addNodes(&deviceMenu, text_table1[15], TFT_ORANGE, NULL, UPDATE, [this]() {
    wifi_ble_scan_obj.currentScanMode = OTA_UPDATE;
    this->changeMenu(&whichUpdateMenu);
  });

  this->addNodes(&deviceMenu, "Save/Load Files", TFT_CYAN, NULL, SD_UPDATE, [this]() {
    this->changeMenu(&saveFileMenu);
  });

  this->addNodes(&deviceMenu, text_table1[16], TFT_GREEN, NULL, LANGUAGE, [this]() {

    wifi_ble_scan_obj.currentScanMode = SHOW_INFO;
    this->changeMenu(&languageMenu);   
  });
  
  this->addNodes(&deviceMenu, text_table1[17], TFT_WHITE, NULL, DEVICE_INFO, [this]() {
    wifi_ble_scan_obj.currentScanMode = SHOW_INFO;
    this->changeMenu(&infoMenu);
    wifi_ble_scan_obj.RunInfo();
  });

  this->addNodes(&deviceMenu, text08, TFT_NAVY, NULL, KEYBOARD_ICO, [this]() {
    this->changeMenu(&settingsMenu);
  });

  #ifdef HAS_SD
    if (sd_obj.supported) {
      this->addNodes(&deviceMenu, "Delete SD Files", TFT_CYAN, NULL, SD_UPDATE, [this]() {
        #ifndef HAS_ILI9341
          #ifdef HAS_BUTTONS
            this->changeMenu(&sdDeleteMenu);
          #endif
        #endif
      });
    }
  #endif

  #ifdef HAS_SD
    #ifndef HAS_ILI9341
      #ifdef HAS_BUTTONS
        sdDeleteMenu.parentMenu = &deviceMenu;
        this->addNodes(&sdDeleteMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
          this->changeMenu(sdDeleteMenu.parentMenu);
        });
      #endif
    #endif
  #endif

  // Save Files Menu
  saveFileMenu.parentMenu = &deviceMenu;
  this->addNodes(&saveFileMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(saveFileMenu.parentMenu);
  });
  this->addNodes(&saveFileMenu, "Save APs", TFT_NAVY, NULL, SD_UPDATE, [this]() {
    this->changeMenu(&saveAPsMenu);
    wifi_ble_scan_obj.RunSaveAPList();
  });
  this->addNodes(&saveFileMenu, "Load APs", TFT_BLUE, NULL, SD_UPDATE, [this]() {
    this->changeMenu(&loadAPsMenu);
    wifi_ble_scan_obj.RunLoadAPList();
  });
  this->addNodes(&saveFileMenu, "Save Airtags", TFT_WHITE, NULL, SD_UPDATE, [this]() {
    this->changeMenu(&saveAPsMenu);
    wifi_ble_scan_obj.RunSaveATList();
  });
  this->addNodes(&saveFileMenu, "Load Airtags", TFT_WHITE, NULL, SD_UPDATE, [this]() {
    this->changeMenu(&loadAPsMenu);
    wifi_ble_scan_obj.RunLoadATList();
  });

  saveAPsMenu.parentMenu = &saveFileMenu;
  this->addNodes(&saveAPsMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(saveAPsMenu.parentMenu);
  });

  loadAPsMenu.parentMenu = &saveFileMenu;
  this->addNodes(&loadAPsMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(loadAPsMenu.parentMenu);
  });

  saveATsMenu.parentMenu = &saveFileMenu;
  this->addNodes(&saveATsMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(saveATsMenu.parentMenu);
  });

  loadATsMenu.parentMenu = &saveFileMenu;
  this->addNodes(&loadATsMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(loadATsMenu.parentMenu);
  });

  // GPS Menu
  #ifdef HAS_GPS
    if (gps_obj.getGpsModuleStatus()) {
      this->addNodes(&deviceMenu, "GPS Data", TFT_RED, NULL, GPS_MENU, [this]() {
        wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_GPS_DATA;
        this->changeMenu(&gpsInfoMenu);
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_GPS_DATA, TFT_CYAN);
      });

      this->addNodes(&deviceMenu, "NMEA Stream", TFT_ORANGE, NULL, GPS_MENU, [this]() {
        wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_GPS_NMEA;
        this->changeMenu(&gpsInfoMenu);
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_GPS_NMEA, TFT_ORANGE);
      });

      // GPS Info Menu
      gpsInfoMenu.parentMenu = &deviceMenu;
      this->addNodes(&gpsInfoMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
        wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
        wifi_ble_scan_obj.StartScan(WIFI_SCAN_OFF);
        this->changeMenu(gpsInfoMenu.parentMenu);
      }); 
    }
  #endif

  // Settings menu
  // Device menu
  settingsMenu.parentMenu = &deviceMenu;
  this->addNodes(&settingsMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    changeMenu(settingsMenu.parentMenu);
  });
  for (int i = 0; i < settings_obj.getNumberSettings(); i++) {
    if (this->callSetting(settings_obj.setting_index_to_name(i)) == "bool")
      this->addNodes(&settingsMenu, settings_obj.setting_index_to_name(i), TFT_LIGHTGREY, NULL, 0, [this, i]() {
      settings_obj.toggleSetting(settings_obj.setting_index_to_name(i));
      this->changeMenu(&specSettingMenu);
      this->displaySetting(settings_obj.setting_index_to_name(i), &settingsMenu, i + 1);
    }, settings_obj.loadSetting<bool>(settings_obj.setting_index_to_name(i)));
  }

  // Specific setting menu
  specSettingMenu.parentMenu = &settingsMenu;
  addNodes(&specSettingMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    this->changeMenu(specSettingMenu.parentMenu);
  });
 
  // Select update
  whichUpdateMenu.parentMenu = &deviceMenu;
  this->addNodes(&whichUpdateMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
    wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
    this->changeMenu(whichUpdateMenu.parentMenu);
  });
  #ifdef HAS_SD
    if (sd_obj.supported) addNodes(&whichUpdateMenu, text_table1[40], TFT_MAGENTA, NULL, SD_UPDATE, [this]() {
      wifi_ble_scan_obj.currentScanMode = OTA_UPDATE;
      this->changeMenu(&confirmMenu);
    });

    // Confirm SD update menu
    confirmMenu.parentMenu = &whichUpdateMenu;
    this->addNodes(&confirmMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
      this->changeMenu(confirmMenu.parentMenu);
    });
    this->addNodes(&confirmMenu, text14, TFT_ORANGE, NULL, UPDATE, [this]() {
      wifi_ble_scan_obj.currentScanMode = OTA_UPDATE;
      this->changeMenu(&failedUpdateMenu);
      sd_obj.runUpdate();
    });
  #endif

	// Web Update
	updateMenu.parentMenu = &deviceMenu;

	// Failed update menu
	failedUpdateMenu.parentMenu = &whichUpdateMenu;
	this->addNodes(&failedUpdateMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
		wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
		this->changeMenu(failedUpdateMenu.parentMenu);
	});

	// Device info menu
	infoMenu.parentMenu = &deviceMenu;
	
	this->addNodes(&infoMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
		wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
		this->changeMenu(infoMenu.parentMenu);
	});

	//language info menu
	languageMenu.parentMenu = &deviceMenu;

	this->addNodes(&languageMenu, text09, TFT_LIGHTGREY, NULL, 0, [this]() {
      wifi_ble_scan_obj.currentScanMode = WIFI_SCAN_OFF;
      this->changeMenu(infoMenu.parentMenu);
	});
  // Set the current menu to the mainMenu
  this->changeMenu(&mainMenu);

  this->initTime = millis();
}

#if (!defined(HAS_ILI9341) && defined(HAS_BUTTONS))
  void MenuFunctions::miniKeyboard(Menu * targetMenu) {
    // Prepare a char array and reset temp SSID string
    extern LinkedList<ssid>* ssids;

    bool pressed = true;

    wifi_ble_scan_obj.current_mini_kb_ssid = "";

    if (c_btn.isHeld()) {
      while (!c_btn.justReleased())
        delay(1);
    }

    int str_len = wifi_ble_scan_obj.alfa.length() + 1; 

    char char_array[str_len];

    wifi_ble_scan_obj.alfa.toCharArray(char_array, str_len);
  }
#endif



// Function to change menu
void MenuFunctions::changeMenu(Menu * menu)
{
	// 进入到窗体以后会再次刷新显示会不会好一点？
	if(g_block_lvgl == true)
	{
		reshow_LVGL_menu();
	}

	display_obj.initScrollValues();
	display_obj.setupScrollArea(TOP_FIXED_AREA, BOT_FIXED_AREA);
	display_obj.tft.init();
	current_menu = menu;

	// warning############
	// 一定不要建立
	// 这里就是旧的button ui
	// 会与lvgl的btn产生严重冲突
	// buildButtons(menu);
	// warning############

	// 使用 LVGL 按钮替代原来的 buildButtons
	// 创建lvgl格式的按钮
	createLVGLButtons(menu,0);
	// 显示当前页面
  displayCurrentMenu(0);

	// 只渲染LVGL区域
	g_limit_to_container = true;
	lv_obj_get_coords(button_container, &g_btn_cont_area);
	
}

// Function to show all MenuNodes in a Menu
void MenuFunctions::showMenuList(Menu * menu, int layer)
{
  // Iterate through all of the menu nodes in the menu
  for (uint8_t i = 0; i < menu->list->size(); i++)
  {
    // Depending on layer, indent
    for (uint8_t x = 0; x < layer * 4; x++)
      Serial.print(" ");
    Serial.print("Node: ");
    Serial.println(menu->list->get(i).name);
  }
  Serial.println();
}


// Function to add MenuNodes to a menu
void MenuFunctions::addNodes(Menu * menu, String name, uint16_t color, Menu * child, int place, std::function<void()> callable, bool selected, String command)
{
  TFT_eSPI_Button new_button;
  menu->list->add(MenuNode{name, false, color, place, &new_button, selected, callable});
  //menu->list->add(MenuNode{name, false, color, place, selected, callable});
}

// void MenuFunctions::buildButtons(Menu * menu, int starting_index, String button_name)
// {
//   if (menu->list != NULL)
//   {
//     this->menu_start_index = starting_index;
//     for (uint8_t i = 0; i < menu->list->size(); i++)
//     {
//       TFT_eSPI_Button new_button;
//       char buf[menu->list->get(starting_index + i).name.length() + 1] = {};
//       if (button_name != "")
//         menu->list->get(starting_index + i).name.toCharArray(buf, menu->list->get(starting_index + i).name.length() + 1);
//       else
//         button_name.toCharArray(buf, button_name.length() + 1);

//       display_obj.key[i].initButton(&display_obj.tft,
//                                     KEY_X + 0 * (KEY_W + KEY_SPACING_X),
//                                     KEY_Y + i * (KEY_H + KEY_SPACING_Y), // x, y, w, h, outline, fill, text
//                                     KEY_W,
//                                     KEY_H,
//                                     TFT_BLACK, // Outline
//                                     TFT_BLACK, // Fill
//                                     menu->list->get(starting_index + i).color, // Text
//                                     buf,
//                                     KEY_TEXTSIZE);


//       display_obj.key[i].setLabelDatum(BUTTON_PADDING - (KEY_W / 2), 2, ML_DATUM);
//     }
//   }
// }

void MenuFunctions::buildButtons(Menu * menu, int starting_index, String button_name)
{
	if (menu->list != NULL)
	{
		this->menu_start_index = starting_index;
		for (uint8_t i = 0; i < menu->list->size(); i++)
		{
			TFT_eSPI_Button new_button;
			char buf[menu->list->get(starting_index + i).name.length() + 1] = {};
			if (button_name != "")
			menu->list->get(starting_index + i).name.toCharArray(buf, menu->list->get(starting_index + i).name.length() + 1);
			else
			button_name.toCharArray(buf, button_name.length() + 1);

			display_obj.key[i].initButton(&display_obj.tft,
										KEY_X + 0 * (KEY_W + KEY_SPACING_X),
										KEY_Y + i * (KEY_H + KEY_SPACING_Y), // x, y, w, h, outline, fill, text
										KEY_W,
										KEY_H,
										TFT_BLACK, // Outline
										TFT_BLACK, // Fill
										menu->list->get(starting_index + i).color, // Text
										buf,
										KEY_TEXTSIZE);


			display_obj.key[i].setLabelDatum(BUTTON_PADDING - (KEY_W / 2), 2, ML_DATUM);
		}
	}
}





// source
// void MenuFunctions::displayCurrentMenu(uint8_t start_index)
// {
//   //Serial.println(F("Displaying current menu..."));
//   display_obj.clearScreen();
//   display_obj.updateBanner(current_menu->name);
//   display_obj.tft.setTextColor(TFT_LIGHTGREY, TFT_DARKGREY);
//   this->drawStatusBar();

//   if (current_menu->list != NULL)
//   {
//     #ifdef HAS_FULL_SCREEN
//       display_obj.tft.setFreeFont(MENU_FONT);
//     #endif

//     #ifdef HAS_MINI_SCREEN
//       display_obj.tft.setFreeFont(NULL);
//       display_obj.tft.setTextSize(1);
//     #endif
//     for (uint8_t i = start_index; i < current_menu->list->size(); i++)
//     {
//       #ifdef HAS_FULL_SCREEN
//         #ifndef HAS_ILI9341
//           if ((current_menu->list->get(i).selected) || (current_menu->selected == i)) {
//             display_obj.key[i - start_index].drawButton(true, current_menu->list->get(i).name);
//           }
//           else {
//             display_obj.key[i - start_index].drawButton(false, current_menu->list->get(i).name);          
//           }
//         #else
//           display_obj.key[i].drawButton(false, current_menu->list->get(i).name); 
//         #endif
        
//         if ((current_menu->list->get(i).name != text09) && (current_menu->list->get(i).icon != 255))
//           display_obj.tft.drawXBitmap(0,
//                                       KEY_Y + (i - start_index) * (KEY_H + KEY_SPACING_Y) - (ICON_H / 2),
//                                       menu_icons[current_menu->list->get(i).icon],
//                                       ICON_W,
//                                       ICON_H,
//                                       TFT_BLACK,
//                                       current_menu->list->get(i).color);

//       #endif

//       #ifdef HAS_MINI_SCREEN
//         if ((current_menu->selected == i) || (current_menu->list->get(i).selected))
//           display_obj.key[i - start_index].drawButton(true, current_menu->list->get(i).name);
//         else 
//           display_obj.key[i - start_index].drawButton(false, current_menu->list->get(i).name);
//       #endif
//     }
//     display_obj.tft.setFreeFont(NULL);
//   }
// }

static void img_click_cb(lv_obj_t *img, lv_event_t event)
{
    char debug_string[64]="\0";
    snprintf(debug_string,64,"img_click_cb-%d",event);
    Serial.println(debug_string);
    if(event == LV_EVENT_DELETE ) {
        // 设置图片染色为红色
        Serial.println("!!!!!!!!!!! LV_EVENT_RELEASED");
        lv_obj_set_style_local_image_recolor(img, LV_IMG_PART_MAIN, LV_STATE_PRESSED, LV_COLOR_ORANGE);
        lv_obj_set_style_local_image_recolor_opa(img, LV_IMG_PART_MAIN, LV_STATE_PRESSED, LV_OPA_COVER);
        
    }
    else
    {
        Serial.println("!!!!!!!!!!! other func");
        lv_obj_set_style_local_image_recolor(img, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_WHITE);
        lv_obj_set_style_local_image_recolor_opa(img, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_COVER);
        
    }
}


inline static lv_obj_t * inner_create_good_look_btn(lv_obj_t *parent,int btn_width,int btn_height,int btn_pos_x,int btn_pos_y,const char* btn_name)
{
	lv_obj_t *btn = lv_btn_create(parent, NULL);
	lv_obj_set_size(btn, btn_width, btn_height);
	lv_obj_set_pos(btn, btn_pos_x, btn_pos_y);
	// 设置透明背景色
	lv_obj_set_style_local_bg_opa(btn, LV_BTN_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_TRANSP);

	// 设置按钮边界颜色
	lv_obj_set_style_local_border_color(btn, LV_BTN_PART_MAIN, LV_STATE_DEFAULT,LV_COLOR_WHITE);
	lv_obj_set_style_local_border_color(btn, LV_BTN_PART_MAIN, LV_STATE_PRESSED, LV_COLOR_ORANGE);

	// 设置按钮文本颜色
	lv_obj_set_style_local_text_color(btn, LV_BTN_PART_MAIN, LV_STATE_DEFAULT,LV_COLOR_WHITE);
	lv_obj_set_style_local_text_color(btn, LV_BTN_PART_MAIN, LV_STATE_PRESSED, LV_COLOR_ORANGE);

	lv_obj_set_style_local_text_color(btn, LV_IMG_PART_MAIN, LV_STATE_DEFAULT,LV_COLOR_WHITE);
	lv_obj_set_style_local_text_color(btn, LV_IMG_PART_MAIN, LV_STATE_PRESSED, LV_COLOR_ORANGE);

  // 设置圆角弧度
  // 设置为10即可
	lv_obj_set_style_local_radius(btn, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 10);
	lv_obj_set_style_local_border_width(btn, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 2);
	lv_obj_set_style_local_pad_inner(btn, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);

	lv_obj_t *icon = NULL;
	if(strstr(btn_name,"WiFi") != NULL)
	{
		LV_IMG_DECLARE(wifi_20x20);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &wifi_20x20);
		 
	}
	else if(strstr(btn_name,"Bluetooth") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_bluetooth);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_bluetooth);

	}
	else if(strstr(btn_name,"Radio") != NULL || strstr(btn_name,"Monitor") != NULL || strstr(btn_name,"Capture") != NULL || strstr(btn_name,"Scan") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_radio);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_radio);

	}

	else if(strstr(btn_name,"Device") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_device);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_device);
	}
	else if(strstr(btn_name,"Reboot") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_reboot);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_reboot);
	}
	else if(strstr(btn_name,"Back") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_back);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_back);
	}
	else if(strstr(btn_name,"Sniffers") != NULL || strstr(btn_name,"Sniff") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_setting);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_setting);
	}
	else if(strstr(btn_name,"General") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_general);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_general);
	}
	else if(strstr(btn_name,"Back") != NULL)
	{
		// 设置图标
		LV_IMG_DECLARE(image_back);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_back);
	}
	else
	{	
		LV_IMG_DECLARE(image_icon);
		icon = lv_img_create(btn, NULL);
		lv_img_set_src(icon, &image_icon);
	}
	lv_obj_align(icon, btn, LV_ALIGN_IN_TOP_MID, 0, 0);
	lv_obj_set_style_local_image_recolor(icon, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_WHITE);
	lv_obj_set_style_local_image_recolor_opa(icon, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_COVER);
	lv_obj_set_parent_event(icon, true);

	lv_obj_t* label = lv_label_create(btn,NULL);
	// 设置与父容器相关的事件绑定
	lv_obj_set_parent_event(label, true);
  	lv_obj_align(label, btn, LV_ALIGN_OUT_BOTTOM_MID, 0, 0);
	// lv_label_set_recolor(label,true);

	if(strlen(btn_name) >= 15)
	{
		lv_label_set_long_mode(label,  LV_LABEL_LONG_SROLL_CIRC);
	}
	else
	{
		lv_label_set_long_mode(label,  LV_LABEL_LONG_EXPAND);
	}
	
	lv_label_set_text(label, btn_name);
	// 设置长度
	lv_obj_set_width(label, 100);
	lv_obj_align(label, NULL,LV_ALIGN_CENTER, 0, 0);

	lv_obj_set_style_local_text_font(label, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, &lv_font_montserrat_12);
	// lv_obj_refresh_style(label, LV_OBJ_PART_ALL);

	// 取消默认效果
	lv_obj_set_style_local_outline_width(btn, LV_BTN_PART_MAIN, LV_STATE_DEFAULT, 0);
	lv_obj_set_style_local_outline_opa(btn,   LV_BTN_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_TRANSP);
	lv_obj_set_style_local_outline_width(btn, LV_BTN_PART_MAIN, LV_STATE_PRESSED, 0);
	lv_obj_set_style_local_outline_opa(btn,   LV_BTN_PART_MAIN, LV_STATE_PRESSED, LV_OPA_TRANSP);
	lv_obj_set_style_local_outline_width(btn, LV_BTN_PART_MAIN, LV_STATE_FOCUSED, 0);
	lv_obj_set_style_local_outline_opa(btn,   LV_BTN_PART_MAIN, LV_STATE_FOCUSED, LV_OPA_TRANSP);
  
	return btn;
}

void MenuFunctions::createLVGLButtons(Menu* menu, int starting_index) 
{
	if (menu->list != NULL) 
	{
		// 释放已经创建的内存
		// 每次打开新的页面，记得释放原来的页面信息
		if (button_container) 
		{
  			lv_obj_del(button_container);
  			button_container = NULL;
		}
		for (int i = 0; i < BUTTON_ARRAY_LEN; i++) 
			lv_buttons[i] = NULL;

		if(button_container == NULL)
		{
			int screen_width = 240;
			int screen_height = 320 - TOP_FIXED_AREA;
			// 这里添加一些特殊窗体的处理逻辑
			if(menu->name == "Radio Receiver" || menu->name == "Load APs" || menu->name == "Save Airtags" || menu->name == "Load Airtags" || 
				menu->name == "Save APs" || menu->name == "Device Info " || menu->name == "ForcePMKID" || 
				menu->name == "ForceProbe" || menu->name == "SavePCAP" || menu->name == "EnableLED")
			{
				screen_height = 80;
				// char debug[128];
				// snprintf(debug,128,"open menu name is :%s and screen_height is :%d",menu->name.c_str(),screen_height);
				// Serial.println(debug);
			}
			// 特殊框体，需要隐藏、缩小菜单
			int btn_height = 60;
			// 这是主窗体
			button_container = lv_obj_create(lv_scr_act(),NULL);
			lv_obj_set_size(button_container, screen_width, screen_height);
			lv_obj_set_pos(button_container, 0, TOP_FIXED_AREA);
			// 设置黑色背景
			lv_obj_set_style_local_bg_color(button_container,LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_BLACK);
			lv_obj_set_style_local_radius(button_container, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);
			lv_obj_set_style_local_border_width(button_container, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);
			lv_obj_set_style_local_pad_inner(button_container, LV_OBJ_PART_MAIN, LV_STATE_DEFAULT, 0);

			// 一行两列式布局
			for (uint8_t i = 0; i < menu->list->size() && i < BUTTON_ARRAY_LEN; i++)
			{
				int colunm = i /2;
				int margin_offset = 5;
				if(i == 0 || i % 2 == 0)
				{
					lv_buttons[i]=inner_create_good_look_btn(
						button_container,
						KEY_W/2 - 10,
						btn_height, 
						margin_offset,
						(margin_offset + btn_height)*colunm ,
						menu->list->get(starting_index + i).name.c_str());
				}
				else
				{
					lv_buttons[i]=inner_create_good_look_btn(
						button_container,
						KEY_W/2 - 10,
						btn_height,
						KEY_W/2+margin_offset,
						(margin_offset + btn_height)*colunm ,
						menu->list->get(starting_index + i).name.c_str());
				}

				// 设置回调函数
				lv_obj_set_event_cb(lv_buttons[i], button_event_cb);
				// 存储菜单项索引作为用户数据
        lv_obj_set_user_data(lv_buttons[i], (void*)(intptr_t)(starting_index + i));
			}
		}
	}
}

void MenuFunctions::button_event_cb(lv_obj_t * btn, lv_event_t event) {
  extern MenuFunctions menu_function_obj;
  // stack数据结构
  lv_obj_t *icon = lv_obj_get_child(btn, NULL);
  lv_obj_t *label = lv_obj_get_child(btn, icon);
	if(event == LV_EVENT_RELEASED)
	{
		// 获取按钮索引
		int button_index = (int)(intptr_t)lv_obj_get_user_data(btn);
		// 执行对应的菜单项功能
		if (button_index < menu_function_obj.current_menu->list->size()) 
		{
			menu_function_obj.current_menu->list->get(button_index).callable();
		}
	}
    else 
    {
		if(icon)
		{
			// Serial.println("set icon color");	
			lv_obj_set_style_local_image_recolor(icon, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_ORANGE);
			lv_obj_set_style_local_image_recolor_opa(icon, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_COVER);
		}
		if(label)
		{
			// Serial.println("set label color");
			lv_obj_set_style_local_image_recolor(label, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_ORANGE);
			lv_obj_set_style_local_image_recolor_opa(label, LV_IMG_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_COVER);
		}
    }
}

void MenuFunctions::displayCurrentMenu(uint8_t start_index) 
{
  display_obj.clearScreen();
  display_obj.updateBanner(current_menu->name);
  display_obj.tft.setTextColor(TFT_LIGHTGREY, TFT_DARKGREY);
  this->drawStatusBar();
}

/// @brief 隐藏LVGL菜单
void MenuFunctions::hiden_LVGL_menu()
{
	// 用于跳过LVGL重绘回调函数
	g_block_lvgl = true;
	if(button_container)
	{
		lv_obj_set_hidden(button_container,true);
	}
	lv_task_handler();
}

/// @brief 再次显示LVGL菜单
void MenuFunctions::reshow_LVGL_menu()
{
	// 用于跳过LVGL重绘回调函数
	g_block_lvgl = false;
	// 不为空才考虑进行重绘菜单
	if(button_container)
	{
		lv_obj_set_hidden(button_container,false);
		lv_task_handler();
	}
}

#endif
