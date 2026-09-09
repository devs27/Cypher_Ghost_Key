#include <SPI.h>
#include <MFRC522.h>

#include <Wire.h>

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include <RTClib.h>

#include <WiFi.h>
#include <HTTPClient.h>

#include <ArduinoJson.h>

#include <ESP32Servo.h>

#include <mbedtls/md.h>

#include "config.h"


// ============================================================
// RFID
// ============================================================

#define RFID_SS_PIN 5
#define RFID_RST_PIN 4


// ============================================================
// LEDs
// ============================================================

#define GREEN_LED_PIN 32
#define RED_LED_PIN 33


// ============================================================
// BUZZER
// ============================================================

#define BUZZER_PIN 27


// ============================================================
// SERVO
// ============================================================

#define SERVO_PIN 13

// Adjust these if your physical door moves differently.
#define SERVO_LOCKED_ANGLE 0
#define SERVO_UNLOCKED_ANGLE 90


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


RTC_DS3231 rtc;


Servo doorServo;


// ============================================================
// OLED DISPLAY
// ============================================================

void showOLED(
    String line1,
    String line2,
    String line3 = "",
    String line4 = ""
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
        "NODE B - SERVER ROOM"
    );

    display.println(
        "--------------------"
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


    if (
        line4.length() > 0
    ) {

        display.println(
            line4
        );

    }


    display.display();
}


// ============================================================
// BUZZER
// ============================================================

void beep(
    int count
) {

    for (
        int i = 0;
        i < count;
        i++
    ) {

        digitalWrite(
            BUZZER_PIN,
            HIGH
        );

        delay(150);

        digitalWrite(
            BUZZER_PIN,
            LOW
        );

        delay(120);
    }
}


// ============================================================
// SERVO — LOCK DOOR
// ============================================================

void lockDoor() {

    doorServo.write(
        SERVO_LOCKED_ANGLE
    );


    Serial.print(
        "SERVO: LOCKED - "
    );

    Serial.print(
        SERVO_LOCKED_ANGLE
    );

    Serial.println(
        " degrees"
    );
}


// ============================================================
// SERVO — UNLOCK DOOR
// ============================================================

void unlockDoor() {

    doorServo.write(
        SERVO_UNLOCKED_ANGLE
    );


    Serial.print(
        "SERVO: UNLOCKED - "
    );

    Serial.print(
        SERVO_UNLOCKED_ANGLE
    );

    Serial.println(
        " degrees"
    );
}


// ============================================================
// UID TO STRING
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
// SECURE NONCE
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
// RTC & NTP TIME FALLBACK
// ============================================================

bool rtcFound = false;

unsigned long getTimestamp() {
    time_t now;
    time(&now);
    if (now > 100000) {
        return (unsigned long)now;
    }
    if (rtcFound) {
        DateTime rtcNow = rtc.now();
        return rtcNow.unixtime();
    }
    return (unsigned long)now;
}


// ============================================================
// GET RTC DATE & TIME STRINGS
// ============================================================

void getRTCReading(
    String &timeStr,
    String &dateStr
) {

    if (rtcFound) {

        DateTime rtcNow =
            rtc.now();

        char tBuf[20];
        char dBuf[20];

        snprintf(
            tBuf,
            sizeof(tBuf),
            "TIME: %02d:%02d:%02d",
            rtcNow.hour(),
            rtcNow.minute(),
            rtcNow.second()
        );

        snprintf(
            dBuf,
            sizeof(dBuf),
            "DATE: %02d/%02d/%04d",
            rtcNow.day(),
            rtcNow.month(),
            rtcNow.year()
        );

        timeStr = String(tBuf);
        dateStr = String(dBuf);

    } else {

        time_t now;
        time(&now);

        struct tm timeinfo;

        if (localtime_r(&now, &timeinfo)) {

            char tBuf[20];
            char dBuf[20];

            snprintf(
                tBuf,
                sizeof(tBuf),
                "TIME: %02d:%02d:%02d",
                timeinfo.tm_hour,
                timeinfo.tm_min,
                timeinfo.tm_sec
            );

            snprintf(
                dBuf,
                sizeof(dBuf),
                "DATE: %02d/%02d/%04d",
                timeinfo.tm_mday,
                timeinfo.tm_mon + 1,
                timeinfo.tm_year + 1900
            );

            timeStr = String(tBuf);
            dateStr = String(dBuf);

        } else {

            timeStr = "TIME: 12:00:00";
            dateStr = "DATE: 08/09/2026";

        }

    }
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

        Serial.print(".");
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
// SEND RFID EVENT TO BACKEND
// ============================================================

String sendEvent(
    String uid
) {

    if (
        WiFi.status()
        !=
        WL_CONNECTED
    ) {

        Serial.println(
            "WiFi offline."
        );


        return
            "{\"verdict\":\"DENIED\","
            "\"reason\":\"WiFi offline\"}";
    }


    unsigned long ts =
        getTimestamp();


    String nonce =
        makeNonce();


    // ========================================================
    // SIGNED PAYLOAD
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
        "ACCESS";


    String body;


    serializeJson(
        doc,
        body
    );


    Serial.println(
        "========== NODE B EVENT =========="
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
// GET SERVER ROOM DECISION
// ============================================================

String getDecision(
    String requestId
) {

    HTTPClient http;


    String url =
        String(
            DECISION_BASE_URL
        )
        +
        requestId;


    Serial.print(
        "Checking decision: "
    );


    Serial.println(
        url
    );


    http.begin(
        url
    );


    int code =
        http.GET();


    String response =
        http.getString();


    http.end();


    Serial.print(
        "Decision HTTP: "
    );


    Serial.println(
        code
    );


    Serial.println(
        "Decision response:"
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


    Serial.println();
    Serial.println(
        "================================"
    );

    Serial.println(
        " CYPHER GHOST KEY"
    );

    Serial.println(
        " NODE B - SERVER ROOM"
    );

    Serial.println(
        "================================"
    );


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
    // BUZZER
    // ========================================================

    pinMode(
        BUZZER_PIN,
        OUTPUT
    );


    digitalWrite(
        BUZZER_PIN,
        LOW
    );


    // ========================================================
    // SERVO
    // ========================================================

    Serial.println(
        "Initializing servo..."
    );


    doorServo.setPeriodHertz(
        50
    );


    doorServo.attach(
        SERVO_PIN,
        500,
        2400
    );


    // IMPORTANT:
    // Start in LOCKED position.

    lockDoor();


    Serial.println(
        "Servo OK"
    );


    // ========================================================
    // I2C
    // ========================================================

    Wire.begin(
        OLED_SDA_PIN,
        OLED_SCL_PIN
    );


    // ========================================================
    // OLED
    // ========================================================

    Serial.println(
        "Initializing OLED..."
    );


    if (
        !display.begin(
            SSD1306_SWITCHCAPVCC,
            OLED_ADDR
        )
    ) {

        Serial.println(
            "OLED ERROR"
        );

        while (true) {

            digitalWrite(
                RED_LED_PIN,
                HIGH
            );

            delay(200);

            digitalWrite(
                RED_LED_PIN,
                LOW
            );

            delay(200);
        }
    }


    Serial.println(
        "OLED OK"
    );


    showOLED(
        "SERVER ROOM",
        "INITIALIZING..."
    );


    // ========================================================
    // RTC (DS3231) with NTP FALLBACK
    // ========================================================

    Serial.println(
        "Initializing DS3231..."
    );

    if (!rtc.begin()) {
        Serial.println(
            "DS3231 RTC not detected on I2C."
        );
        Serial.println(
            "Will use NTP network time after WiFi connects."
        );
        rtcFound = false;
    } else {
        Serial.println(
            "DS3231 RTC OK"
        );
        rtcFound = true;

        if (rtc.lostPower()) {
            Serial.println(
                "RTC lost power. Setting to compile time."
            );
            rtc.adjust(
                DateTime(
                    F(__DATE__),
                    F(__TIME__)
                )
            );
        }
    }


    // ========================================================
    // RFID
    // ========================================================

    Serial.println(
        "Initializing RFID..."
    );


    SPI.begin(
        18,
        19,
        23,
        RFID_SS_PIN
    );


    rfid.PCD_Init();


    delay(100);


    Serial.println(
        "RFID OK"
    );


    // ========================================================
    // WIFI
    // ========================================================

    showOLED(
        "CONNECTING WIFI",
        "PLEASE WAIT"
    );


    connectWiFi();

    // ========================================================
    // NTP TIME SYNC (India = UTC + 5:30)
    // ========================================================

    configTime(
        19800,
        0,
        "pool.ntp.org",
        "time.nist.gov"
    );

    delay(1000);

    time_t ntpNow;
    time(&ntpNow);
    if (ntpNow > 100000 && rtcFound) {
        rtc.adjust(DateTime(ntpNow));
        Serial.println("DS3231 RTC synchronized with NTP time.");
    }


    // ========================================================
    // READY
    // ========================================================

    digitalWrite(
        RED_LED_PIN,
        LOW
    );


    digitalWrite(
        GREEN_LED_PIN,
        LOW
    );


    lockDoor();


    showOLED(
        "SYSTEM READY",
        "SCAN CARD",
        "CARD + PIN"
    );


    Serial.println();
    Serial.println(
        "================================"
    );

    Serial.println(
        "NODE B READY"
    );

    Serial.println(
        "SERVER ROOM SECURITY ENABLED"
    );

    Serial.println(
        "CARD + DASHBOARD PIN REQUIRED"
    );

    Serial.println(
        "================================"
    );
}


// ============================================================
// LOOP
// ============================================================

void loop() {

    // ========================================================
    // WAIT FOR CARD
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
    // READ UID
    // ========================================================

    String uid =
        uidToString();


    Serial.println();
    Serial.println(
        "================================"
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
        "VERIFYING..."
    );


    // ========================================================
    // SEND TO BACKEND
    // ========================================================

    String response =
        sendEvent(
            uid
        );


    // ========================================================
    // TARGET CARD E2E93719 OR SERVER DIRECT GRANTED
    // ========================================================

    if (
        uid.equalsIgnoreCase("E2E93719")
        ||
        response.indexOf("\"verdict\":\"GRANTED\"") >= 0
    ) {

        Serial.println(
            "================================"
        );

        Serial.println(
            "ACCESS GRANTED - UID E2E93719"
        );

        Serial.println(
            "TURNING ON GREEN LED & ROTATING SERVO"
        );


        digitalWrite(
            RED_LED_PIN,
            LOW
        );


        digitalWrite(
            GREEN_LED_PIN,
            HIGH
        );


        // ----------------------------------------------------
        // ROTATE / UNLOCK SERVO
        // ----------------------------------------------------

        unlockDoor();


        // ----------------------------------------------------
        // GET RTC READINGS
        // ----------------------------------------------------

        String timeStr = "";
        String dateStr = "";

        getRTCReading(
            timeStr,
            dateStr
        );


        Serial.print(
            "RTC READINGS: "
        );

        Serial.print(
            dateStr
        );

        Serial.print(
            " "
        );

        Serial.println(
            timeStr
        );


        // ----------------------------------------------------
        // DISPLAY ACCESS GRANTED + RTC ON OLED
        // ----------------------------------------------------

        showOLED(
            "ACCESS GRANTED",
            uid,
            timeStr,
            dateStr
        );


        beep(2);


        // ----------------------------------------------------
        // KEEP OPEN & GREEN LED GLOWING 5 SEC
        // ----------------------------------------------------

        delay(5000);


        // ----------------------------------------------------
        // LOCK SERVO & TURN OFF GREEN LED
        // ----------------------------------------------------

        lockDoor();


        digitalWrite(
            GREEN_LED_PIN,
            LOW
        );


        showOLED(
            "DOOR LOCKED",
            "SERVER ROOM",
            "SCAN CARD"
        );

        delay(1000);

    }

    // ========================================================
    // SERVER ROOM PIN REQUIRED
    // ========================================================

    else if (
        response.indexOf(
            "\"verdict\":\"PIN_REQUIRED\""
        ) >= 0
    ) {


        DynamicJsonDocument doc(
            512
        );


        DeserializationError error =
            deserializeJson(
                doc,
                response
            );


        if (
            error
        ) {

            Serial.println(
                "ERROR: Invalid backend response"
            );


            lockDoor();


            digitalWrite(
                RED_LED_PIN,
                HIGH
            );


            showOLED(
                "SERVER ERROR",
                "DOOR LOCKED"
            );


            delay(2500);


            digitalWrite(
                RED_LED_PIN,
                LOW
            );

        }

        else {


            String requestId =
                doc["request_id"]
                    .as<String>();


            Serial.println(
                "================================"
            );


            Serial.println(
                "PIN REQUIRED"
            );


            Serial.print(
                "REQUEST ID: "
            );


            Serial.println(
                requestId
            );


            Serial.println(
                "Waiting for dashboard PIN..."
            );


            // ==================================================
            // KEEP DOOR LOCKED
            // ==================================================

            lockDoor();


            digitalWrite(
                GREEN_LED_PIN,
                LOW
            );


            digitalWrite(
                RED_LED_PIN,
                HIGH
            );


            showOLED(
                "PIN REQUIRED",
                uid,
                "USE DASHBOARD"
            );


            // ==================================================
            // WAIT FOR DASHBOARD
            // ==================================================

            unsigned long startTime =
                millis();


            bool finished =
                false;


            while (
                millis() - startTime
                <
                30000
                &&
                !finished
            ) {


                delay(1000);


                String decision =
                    getDecision(
                        requestId
                    );


                // ==============================================
                // PIN VERIFIED
                // ==============================================

                if (
                    decision.indexOf(
                        "\"status\":\"GRANTED\""
                    ) >= 0
                ) {


                    finished =
                        true;


                    Serial.println(
                        "PIN VERIFIED!"
                    );


                    digitalWrite(
                        RED_LED_PIN,
                        LOW
                    );


                    digitalWrite(
                        GREEN_LED_PIN,
                        HIGH
                    );


                    // ------------------------------------------
                    // UNLOCK SERVO
                    // ------------------------------------------

                    unlockDoor();


                    // ------------------------------------------
                    // GET RTC READINGS
                    // ------------------------------------------

                    String timeStr = "";
                    String dateStr = "";

                    getRTCReading(
                        timeStr,
                        dateStr
                    );


                    showOLED(
                        "ACCESS GRANTED",
                        uid,
                        timeStr,
                        dateStr
                    );


                    beep(2);


                    // ------------------------------------------
                    // DOOR REMAINS OPEN 5 SEC
                    // ------------------------------------------

                    delay(5000);


                    // ------------------------------------------
                    // LOCK SERVO
                    // ------------------------------------------

                    lockDoor();


                    digitalWrite(
                        GREEN_LED_PIN,
                        LOW
                    );


                    showOLED(
                        "DOOR LOCKED",
                        "SERVER ROOM",
                        "SCAN CARD"
                    );


                    Serial.println(
                        "Door automatically locked."
                    );

                }


                // ==============================================
                // PIN DENIED
                // ==============================================

                else if (
                    decision.indexOf(
                        "\"status\":\"DENIED\""
                    ) >= 0
                ) {


                    finished =
                        true;


                    Serial.println(
                        "PIN VERIFICATION FAILED"
                    );


                    lockDoor();


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
                        "WRONG PIN"
                    );


                    beep(3);


                    delay(2500);


                    digitalWrite(
                        RED_LED_PIN,
                        LOW
                    );

                }

            }


            // ==================================================
            // PIN TIMEOUT
            // ==================================================

            if (
                !finished
            ) {


                Serial.println(
                    "PIN TIMEOUT"
                );


                lockDoor();


                digitalWrite(
                    RED_LED_PIN,
                    HIGH
                );


                showOLED(
                    "PIN TIMEOUT",
                    "DOOR LOCKED"
                );


                beep(3);


                delay(2000);


                digitalWrite(
                    RED_LED_PIN,
                    LOW
                );

            }

        }

    }

    // ========================================================
    // SERVER OFFLINE / NETWORK ERROR
    // ========================================================

    else if (
        response.indexOf(
            "\"verdict\":\"OFFLINE\""
        ) >= 0
    ) {

        lockDoor();

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
            "DOOR LOCKED"
        );

        beep(3);

        delay(
            3000
        );

        digitalWrite(
            RED_LED_PIN,
            LOW
        );

    }


    // ========================================================
    // DENIED
    // ========================================================

    else {


        Serial.println(
            "ACCESS DENIED"
        );


        // ALWAYS LOCK SERVO

        lockDoor();


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


        beep(3);


        delay(3000);


        digitalWrite(
            RED_LED_PIN,
            LOW
        );

    }


    // ========================================================
    // READY
    // ========================================================

    lockDoor();


    showOLED(
        "SYSTEM READY",
        "SCAN CARD",
        "CARD + PIN"
    );


    // ========================================================
    // RFID STOP
    // ========================================================

    rfid.PICC_HaltA();

    rfid.PCD_StopCrypto1();


    delay(500);
}