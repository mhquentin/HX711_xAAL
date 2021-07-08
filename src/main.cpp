#include <Arduino.h>
#include <EEPROM.h>

#include <config.h>
#include <byteswap.h>

#include <YACL.h>
#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP mcast;
WiFiUDP ntpUDP;

#include <NTPClient.h>
NTPClient timeClient(ntpUDP, "europe.pool.ntp.org", 0, 300 * 1000);

#include <Crypto.h>
#include <ChaChaPoly.h>
ChaChaPoly chacha;

#include <HX711.h>

const int LOADCELL_DOUT_PIN = 13;
const int LOADCELL_SCK_PIN = 12;

HX711 scale;
float calibration_factor = 2450 ; // Defines calibration factor we'll use for calibrating.

#define IETF_ABITES  16
typedef union {
  unsigned char buf[12];
  struct {
    uint64_t sec;
    uint32_t usec; };
} nonce_t;

class Message {
   public:
    const uint8_t *source;
    const char    *dev_type;
    int            msg_type = 0;
    const char    *action;
    CBORPair       body;
    Message();
    void dump();
};

Message::Message() {
}

void wifiInit() {
  Serial.print("# Init WiFi\n");
  WiFi.begin(SSID, PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  Serial.print("# WiFi connected\n");
  Serial.print("# IP address: ");
  Serial.println(WiFi.localIP());
  mcast.beginMulticast(IPAddress(224,0,29,200),PORT);
}

void Message::dump() {
  Serial.printf("msg_type: %d action: %s\n",msg_type,action);
}

void hexdump(const uint8_t *buf,int size) {
  Serial.print("[");
  for (size_t i=0 ; i < size ; ++i) {
    Serial.print("0x");
	Serial.print(buf[i], HEX);
    Serial.print(",");
	}
  Serial.print("]");
}

void xAALSend(Message msg) {
  unsigned long sec,usec;
  nonce_t nonce;
  uint8_t *cypher; 
  uint16_t size;
  
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }
   CBORArray data = CBORArray();
  // ------------- headers -------------
  // version 
	data.append(7);
  // timestamp
  sec = timeClient.getEpochTime();
  usec = micros();
  data.append(sec);
  data.append(usec);

  // target is a list of address in bytes format.
  // in CBOR an empty list = 0x80, encoded in byte format, this shoud be [0x41,0x80]
  CBOR targets = CBOR();
  const uint8_t * ad = CBORArray(0).to_CBOR();
  targets.encode(ad, 1);
  data.append(targets);

  // ------------- payload -------------
  // source uuid address
  CBORArray buf = CBORArray();
  CBOR source = CBOR();
  source.encode(msg.source,16);
  buf.append(source);
  buf.append(msg.dev_type);
  buf.append(msg.msg_type);
  buf.append(msg.action);
  if (msg.body.length()!=0)
    buf.append(msg.body);

  // ------------- cyphering -------------
  chacha.clear();
  chacha.setKey(XAAL_KEY,32);
  // Nonce 
  nonce.sec =  __bswap_64(sec);
  nonce.usec = __bswap_32(usec);

  chacha.setIV(nonce.buf,12);
  // additionnal data
  chacha.addAuthData(CBORArray(0).to_CBOR(),1);
  // let's cipher & tag the buf
  size = buf.length();
  cypher = (uint8_t *) malloc(sizeof(uint8_t) * (size + IETF_ABITES));
  chacha.encrypt(cypher,(const uint8_t*)buf.to_CBOR(),size);
  // in combined mode ChachaPoly provide auth tag after ciphered data
  chacha.computeTag(cypher+size,IETF_ABITES);
  size = size + IETF_ABITES;

  // adding  cyphered payload
  CBOR tmp = CBOR();
  tmp.encode(cypher,size);
  data.append(tmp);
  
  // ------------- mcast sending ------------
  const uint8_t *cbor_encoded = data.to_CBOR();
  //hexdump(cbor_encoded,data.length());
  mcast.beginMulticastPacket();
  mcast.write(cbor_encoded,data.length());
  mcast.endPacket();
  Serial.print("Sent msg: " );
  msg.dump();
}

void ntpInit() {
  timeClient.update();
  Serial.println("# Time : " + timeClient.getFormattedTime());
}

void HX711Init() {
  Serial.print("\n# Init HX711\n");
  Serial.println("Initializing scale calibration.");  // Prints user commands.
  Serial.println("Please remove all weight from scale.");
  Serial.println("Place known weights on scale one by one.");
  scale.begin(LOADCELL_DOUT_PIN, LOADCELL_SCK_PIN);   // Initializes the scaling process.
  scale.set_scale();
  scale.tare();          // Resets the scale to 0.
}

void sendAlive() {
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "Balance.basic";
  msg.action = "alive";
  msg.body.append("timeout",600);
  xAALSend(msg);
}
void sendDescription() {
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "Balance.basic";
  msg.msg_type = 2; // REPLY
  msg.action = "get_description";
  msg.body.append("vendor_id","Arduino");
  msg.body.append("product_id","ESP32 DEV");
  msg.body.append("info",WiFi.localIP().toString().c_str());
  xAALSend(msg);
}
void sendStatus() {
  
  scale.set_scale(calibration_factor);  // Adjusts the calibration factor.
  scale.wait_ready();
  Serial.print("Reading: ");            // Prints weight readings in .2 decimal kg units.
  Serial.print(scale.get_units(), 2);
  Serial.println(" kg");
  
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "Balance.basic";
  msg.action = "attributes_change";
  msg.body.append("Weight", scale.get_units());
  xAALSend(msg);

  scale.power_down();    // Puts the scale to sleep mode for 3 seconds.
  delay(100);
  scale.power_up();
}

void setup()
{
  Serial.begin(115200);   // Starts serial communication in 115200 baud rate.
  HX711Init();
  wifiInit();
  ntpInit();
}

void loop(){
  static unsigned long last_alive,last_attribute = 0;
  unsigned long now;
  timeClient.update();
  now = timeClient.getEpochTime();
  if (now > (last_alive + 300)) {
    sendAlive();
    sendDescription();
    last_alive = now;
  }
  if (now > (last_attribute + 1)) {
    sendStatus();
    last_attribute = now;
  }
  delay(1000);
}