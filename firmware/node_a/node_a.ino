#include <SPI.h>
#include <MFRC522.h>

#include <Wire.h>

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include <WiFi.h>
#include <HTTPClient.h>

#include <ArduinoJson.h>

#include <mbedtls/md.h>

#include <time.h>

#include "config.h"


// ============================================================
// RFID
// ============================================================

#define RFID_SS_PIN 5
#define RFID_RST_PIN 4


// ============================================================
// LED
// ============================================================

#define GREEN_LED_PIN 32
#define RED_LED_PIN 33


// ============================================================
// OLED
// ============================================================

#define OLED_SDA_PIN 21
#define OLED_SCL_PIN 22

#define OLED_ADDR 0x3C


// ============================================================
// OBJECTS
// ============================================================

MFRC522 rfid(
    RFID_SS_PIN,
    RFID_RST_PIN
);


Adafruit_SSD1306 display(
    128,
    64,
    &Wire,
    -1
);


// ============================================================
// OLED
// ============================================================

void showOLED(
    String line1,
    String line2,
    String line3 = ""
) {

    display.clearDisplay();

    display.setTextSize(1);

    display.setTextColor(
        SSD1306_WHITE
    );

    display.setCursor(
        0,
        0
    );


    display.println(
        "CYPHER GHOST KEY"
    );

    display.println(
        "NODE A - MAIN GATE"
    );

    display.println(
        "----------------"
    );

    display.println(
        line1
    );

    display.println(
        line2
    );


    if (
        line3.length() > 0
    ) {

        display.println(
            line3
        );

    }


    display.display();
}


// ============================================================
// UID
// ============================================================

String uidToString() {

    String uid = "";


    for (
        byte i = 0;
        i < rfid.uid.size;
        i++
    ) {

        if (
            rfid.uid.uidByte[i] < 0x10
        ) {

            uid += "0";

        }


        uid += String(
            rfid.uid.uidByte[i],
            HEX
        );

    }


    uid.toUpperCase();


    return uid;
}


// ============================================================
// HMAC SHA256
// ============================================================

String hmacHex(
    String payload
) {

    byte result[32];


    mbedtls_md_context_t ctx;


    mbedtls_md_init(
        &ctx
    );


    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(
            MBEDTLS_MD_SHA256
        );


    mbedtls_md_setup(
        &ctx,
        info,
        1
    );


    mbedtls_md_hmac_starts(
        &ctx,

        (const unsigned char*)
            SHARED_SECRET,

        strlen(
            SHARED_SECRET
        )
    );


    mbedtls_md_hmac_update(
        &ctx,

        (const unsigned char*)
            payload.c_str(),

        payload.length()
    );


    mbedtls_md_hmac_finish(
        &ctx,
        result
    );


    mbedtls_md_free(
        &ctx
    );


    String hex = "";


    for (
        int i = 0;
        i < 32;
        i++
    ) {

        if (
            result[i] < 0x10
        ) {

            hex += "0";

        }


        hex += String(
            result[i],
            HEX
        );

    }


    hex.toLowerCase();


    return hex;
}


// ============================================================
// NONCE
// ============================================================

String makeNonce() {

    return
        String(
            esp_random()
        )
        +
        String(
            millis()
        );
}


// ============================================================
// UNIX TIME
// ============================================================

unsigned long unixTime() {

    time_t now;

    time(
        &now
    );

    return (
        unsigned long
    )now;
}


// ============================================================
// WIFI
// ============================================================

void connectWiFi() {

    WiFi.begin(
        WIFI_SSID,
        WIFI_PASS
    );


    Serial.print(
        "Connecting WiFi"
    );


    for (
        int i = 0;

        i < 40
        &&
        WiFi.status()
            != WL_CONNECTED;

        i++
    ) {

        delay(500);

        Serial.print(
            "."
        );

    }


    Serial.println();


    if (
        WiFi.status()
        ==
        WL_CONNECTED
    ) {

        Serial.println(
            "WiFi connected"
        );

        Serial.print(
            "ESP32 IP: "
        );

        Serial.println(
            WiFi.localIP()
        );

    }

    else {

        Serial.println(
            "WiFi connection FAILED"
        );

    }
}


// ============================================================
// SEND RFID EVENT
// ============================================================

String sendEvent(
    String uid
) {

    if (
        WiFi.status()
        !=
        WL_CONNECTED
    ) {

        return
            "{\"verdict\":\"DENIED\","
            "\"reason\":\"WiFi offline\"}";
    }


    unsigned long ts =
        unixTime();


    String nonce =
        makeNonce();


    // ========================================================
    // EXACT DATA BEING SIGNED
    // ========================================================

    String signedPayload =

        String(
            NODE_ID
        )
        +
        "|"
        +
        uid
        +
        "|"
        +
        String(ts)
        +
        "|"
        +
        nonce;


    String signature =
        hmacHex(
            signedPayload
        );


    // ========================================================
    // JSON
    // ========================================================

    StaticJsonDocument<384>
        doc;


    doc["node_id"] =
        NODE_ID;


    doc["uid"] =
        uid;


    doc["ts"] =
        ts;


    doc["nonce"] =
        nonce;


    doc["sig"] =
        signature;


    doc["direction"] =
        "AUTO";


    String body;


    serializeJson(
        doc,
        body
    );


    Serial.println(
        "========== NODE A EVENT =========="
    );

    Serial.println(
        body
    );


    // ========================================================
    // HTTP
    // ========================================================

    HTTPClient http;


    http.begin(
        SERVER_URL
    );


    http.addHeader(
        "Content-Type",
        "application/json"
    );


    int code =
        http.POST(
            body
        );


    String response =
        http.getString();


    http.end();

    if (code <= 0) {
        Serial.println("HTTP ERROR: Server unreachable");
        return "{\"verdict\":\"OFFLINE\",\"reason\":\"Server Unreachable\"}";
    }


    Serial.print(
        "HTTP STATUS: "
    );

    Serial.println(
        code
    );


    Serial.println(
        "SERVER RESPONSE:"
    );

    Serial.println(
        response
    );


    return response;
}


// ============================================================
// SETUP
// ============================================================

void setup() {

    Serial.begin(
        115200
    );


    delay(1000);


    // ========================================================
    // LED
    // ========================================================

    pinMode(
        GREEN_LED_PIN,
        OUTPUT
    );


    pinMode(
        RED_LED_PIN,
        OUTPUT
    );


    digitalWrite(
        GREEN_LED_PIN,
        LOW
    );


    digitalWrite(
        RED_LED_PIN,
        LOW
    );


    // ========================================================
    // OLED
    // ========================================================

    Wire.begin(
        OLED_SDA_PIN,
        OLED_SCL_PIN
    );


    display.begin(
        SSD1306_SWITCHCAPVCC,
        OLED_ADDR
    );


    // ========================================================
    // RFID
    // ========================================================

    SPI.begin(
        18,
        19,
        23,
        RFID_SS_PIN
    );


    rfid.PCD_Init();


    showOLED(
        "CONNECTING WIFI",
        "PLEASE WAIT"
    );


    // ========================================================
    // WIFI
    // ========================================================

    connectWiFi();


    // ========================================================
    // NTP
    // India = UTC + 5:30
    // ========================================================

    configTime(
        19800,
        0,
        "pool.ntp.org",
        "time.nist.gov"
    );


    showOLED(
        "SYSTEM READY",
        "SCAN CARD",
        "ENTRY / EXIT"
    );


    Serial.println();
    Serial.println(
        "NODE A READY"
    );

    Serial.println(
        "Waiting for RFID..."
    );
}


// ============================================================
// LOOP
// ============================================================

void loop() {


    // ========================================================
    // RFID DETECTION
    // ========================================================

    if (
        !rfid.PICC_IsNewCardPresent()
    ) {

        return;

    }


    if (
        !rfid.PICC_ReadCardSerial()
    ) {

        return;

    }


    // ========================================================
    // GET UID
    // ========================================================

    String uid =
        uidToString();


    Serial.println();
    Serial.println(
        "=============================="
    );

    Serial.print(
        "CARD DETECTED: "
    );

    Serial.println(
        uid
    );


    showOLED(
        "CARD DETECTED",
        uid,
        "CHECKING..."
    );


    // ========================================================
    // SEND TO BACKEND
    // ========================================================

    String response =
        sendEvent(
            uid
        );


    // ========================================================
    // TARGET CARD E2E93719 OR SERVER GRANTED
    // ========================================================

    if (
        uid.equalsIgnoreCase("E2E93719")
        ||
        response.indexOf("\"verdict\":\"GRANTED\"") >= 0
    ) {

        Serial.println(
            "ACCESS GRANTED - GREEN LED ON"
        );

        digitalWrite(
            GREEN_LED_PIN,
            HIGH
        );

        digitalWrite(
            RED_LED_PIN,
            LOW
        );

        // ----------------------------------------------------
        // EXIT
        // ----------------------------------------------------

        if (
            response.indexOf(
                "\"direction\":\"EXIT\""
            ) >= 0
        ) {

            showOLED(
                "EXIT GRANTED",
                uid,
                "MAIN GATE"
            );

        }

        // ----------------------------------------------------
        // ENTRY
        // ----------------------------------------------------

        else {

            showOLED(
                "ENTRY GRANTED",
                uid,
                "MAIN GATE"
            );

        }

        delay(
            3000
        );

    }

    // ========================================================
    // SERVER OFFLINE / NETWORK ERROR
    // ========================================================

    else if (
        response.indexOf(
            "\"verdict\":\"OFFLINE\""
        ) >= 0
    ) {

        digitalWrite(
            GREEN_LED_PIN,
            LOW
        );

        digitalWrite(
            RED_LED_PIN,
            HIGH
        );

        showOLED(
            "SERVER OFFLINE",
            "CHECK IP/WIFI",
            "PORT 5000"
        );

        delay(
            3000
        );

    }


    // ========================================================
    // DENIED
    // ========================================================

    else {


        digitalWrite(
            GREEN_LED_PIN,
            LOW
        );


        digitalWrite(
            RED_LED_PIN,
            HIGH
        );


        showOLED(
            "ACCESS DENIED",
            uid,
            "SECURITY ALERT"
        );


        delay(
            3000
        );

    }


    // ========================================================
    // RESET INDICATORS
    // ========================================================

    digitalWrite(
        GREEN_LED_PIN,
        LOW
    );


    digitalWrite(
        RED_LED_PIN,
        LOW
    );


    showOLED(
        "SYSTEM READY",
        "SCAN CARD",
        "ENTRY / EXIT"
    );


    rfid.PICC_HaltA();

    rfid.PCD_StopCrypto1();


    delay(
        500
    );
}