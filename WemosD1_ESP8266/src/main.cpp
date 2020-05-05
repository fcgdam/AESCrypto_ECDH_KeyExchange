#include "AES.h"
#include "base64.h"

// For now it is for running on the ESP8266
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <ESP8266HTTPClient.h>
#include <WiFiUdp.h>
#include <SimpleTimer.h>
#include <ArduinoJson.h>
#include <Curve25519.h>

// CHANGE THE FOLLOWING PARAMETERS: THE AP Credentials and the NodeJs serve
String      SSID = "apapap";
String      PASS = "passpass";

// Node server IP
String      NODEServer_Address = "192.168.1.68";
String      NODEServer_Port    = "8087";

WiFiServer  server(80);
HTTPClient  http;
AES         aes;
AES         aesDecript;

// The necessary encryption information: First the pre-shared key.
//byte        key[] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
byte        key[16];    // To hold the AES128 key. Note:

// The unitialized Initialization vector
byte        my_iv[N_BLOCK] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// For holding ECDH data
static constexpr size_t KEY_SIZE = 32;

uint8_t m_publicKey[KEY_SIZE];          // This device private key
uint8_t m_privateKey[KEY_SIZE];         // This device public key

uint8_t m_fpublickey[KEY_SIZE];         // The foreign device public key.
uint8_t m_shkey[KEY_SIZE];              // The calculated shared key

// Working variables for hold data
char        b64data[200];
byte        cipher[1000];
byte        cipherDecrypt[1000];
byte        iv [N_BLOCK] ;

// For holding the server response
DynamicJsonDocument jsonDoc( 1024 );

// Timer to send sample data at intervals
SimpleTimer timer;

unsigned long counter = 0;              // To have some changing data to send...

// ESP8266 generate hardware random based numbers.
uint8_t getrnd() {
    uint8_t really_random = *(volatile uint8_t *)0x3FF20E44;
    return really_random;
}

// Generate a random initialization vector
void gen_iv(byte  *iv) {
    for (int i = 0 ; i < N_BLOCK ; i++ ) {
        iv[i]= (byte) getrnd();
    }
}

// Execute HTTP Post request to the Node Server
void sendData( String data, String iv)  {
    String url = "http://" + NODEServer_Address + ":" + NODEServer_Port + "/setdata";

    http.begin( url );
    http.addHeader( "content-type" , "application/json");

    // Post the message to the server
    http.POST("{\"iv\":\""+iv+"\",\"data\":\""+data+"\"}");
    http.end();
}

// Simple way to obtain values from strings.
String getValue(String data, char separator, int index)
{
    int found = 0;
    int strIndex[] = { 0, -1 };
    int maxIndex = data.length() - 1;

    for (int i = 0; i <= maxIndex && found <= index; i++) {
        if (data.charAt(i) == separator || i == maxIndex) {
            found++;
            strIndex[0] = strIndex[1] + 1;
            strIndex[1] = (i == maxIndex) ? i+1 : i;
        }
    }
    return found > index ? data.substring(strIndex[0], strIndex[1]) : "";
}

// Some helper functions------------------------------------------------------------------------
//
// Prints data in HEX format on the serial port
void    printHex(const char *label, uint8_t *data, int len) {
    Serial.printf("%s:\n", label );

    for ( int i = 0; i < len; i++ ) {
        Serial.printf("%02X " , data[i] );
    }
    Serial.printf("\n\n");
}

char    highHex( uint8_t v ) {
    char    c;
    v = ( v >> 4 ) & 0x0F;
    v < 10 ? ( c = '0' + v ) : ( c = 'A' + v - 10 );
    return c;
}

char    lowHex( uint8_t v ) {
    char    c;
    v = v & 0x0F;
    v < 10 ?  (c = '0' + v) : (c = 'A' + v - 10);
    return c;
}

// Converts a byte array to an HEX string representing the byte array.
void    Bytes2Str(char *out, uint8_t *key, int len ) {
    int p = 0;
    for ( int i = 0;  i < len ; i ++ ) {
        out[p++] = highHex( key[i] );
        out[p++] = lowHex( key[i] );
    }
    out[p] = '\0';
}

uint8_t nibble( char c )
{
    if ('0' <= c && c <= '9') return (uint8_t)(c - '0');
    if ('A' <= c && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0;
}

uint8_t  getByte( char c1 , char c2 ) {
    return ( nibble(c1) << 4 ) | nibble(c2);
}

// Converts a String with an HEX representation into a byte array
void Str2Bytes( uint8_t *out, char *in , int len) {
    int p = 0;
    for( int i = 0 ; i < len ; i = i + 2 ) {        
        out[p++] = getByte( in[i] , in[i+1]);
    }
}

//---------------------------------------------------------------------------
// ECDH supporting functions

// Generates the ECDH private and public key pair. 
// The function generates internally a random private key.
void    generateKeys() {
    Curve25519::dh1( m_publicKey, m_privateKey);
}

void    initSession() {
    // We contact the NodeJS server to send our Public key
    // and as a response we receive the Nodejs Public key
    generateKeys();                 // Generate a set of Curve25519 key pair for the DH key Agreement protocol

    // The Server end-point
    String url = "http://" + NODEServer_Address + ":" + NODEServer_Port + "/getSession";

    char    s_pubkey[65];
    Bytes2Str( s_pubkey, m_publicKey, KEY_SIZE );

    // Build the post body
    String postBody = "{\"pubkey\": \"" + String(s_pubkey) +"\"}";

    // Send the request
    http.begin( url );
    http.addHeader("content-type", "application/json");

    int httpCode = http.POST( postBody );
    if (httpCode > 0) {

        String payload = http.getString();
    
        if ( httpCode == 200 ) {            
            deserializeJson( jsonDoc, payload.c_str() );

            // Obtain the foreign public key
            const char *pubkey = jsonDoc["pubkey"];
            if ( pubkey != NULL) {
                Str2Bytes(m_fpublickey, (char *)pubkey, 64 );
                printHex( "Foreign Key: ", m_fpublickey , 32 );

                // Calculate now the shared key
                Curve25519::dh2( m_fpublickey, m_privateKey ); 
                printHex ( "Shared Key", m_fpublickey , 32 );     
                memcpy( m_shkey, m_fpublickey, 32 );
            }               
        }
        else {
            Serial.println("Error on HTTP request a session.");
        }
    }
    http.end();
}

// ====== ENCRYPT =====
void encryptData(String message) {  // OK
    char b64dataIV[64];

    // Generate random IV
    byte ivByteArray[16];                               // The IV's always have the same size used for AES: 16 bytes
    gen_iv( ivByteArray );
    
    b64_encode( b64dataIV, (char *)ivByteArray, N_BLOCK);
    String iv = String(b64dataIV);
    Serial.println ("IV B64: " + iv);
   
    // encrypt message  
    int b64len = b64_encode(b64data, (char *)message.c_str(),message.length()); 
    aes.do_aes_encrypt((byte *)b64data, b64len , cipher, key, 128, ivByteArray);
    
    // Encode the encrypted data in Base64 so that it can be safely transmitted 
    b64_encode(b64data, (char *)cipher, aes.get_size() );
    String data = String(b64data);

    Serial.println("------- Sending data:");
    Serial.println (" Data: " + data);

    Serial.print (" aes.get_size: ");
    Serial.println (aes.get_size());
    Serial.print (" b64data.length: ");
    Serial.println (data.length());
    Serial.println("");
    // Send data to the other server/device
    sendData( data, iv );
}

void hextobyte( char *in , int len , byte *out ) {
    int p = 0;
    for( int i = 0 ; i < len ; i = i + 2 ) {
        out[p] = getByte( in[i] , in[i+1]);        
        p++;
    }
    Serial.println("");
}

// Decrypts incomming data.
void decryptData(String b64data, String IV_base64) { 
    char data_decoded[300];
    char iv_decoded[32];
    byte p_iv[16];

    byte out[300];

    // Data enters encoded in Base64. So decode it.       
    int encrypted_length = b64_decode( data_decoded, (char *)b64data.c_str(), b64data.length());

    // IV is in BASE64 also
    b64_decode( iv_decoded, (char *)IV_base64.c_str(), IV_base64.length());

/*    Serial.println(String( (char *)iv_decoded).c_str());
    unsigned long long my_iv = 0;
    aes.set_IV(my_iv);
    aes.get_IV( f_iv );
    Serial.println("IV to be used: ");
    aes.printArray( f_iv , 16 );
*/
    hextobyte( (char *)iv_decoded, 32, (unsigned char *)p_iv );

//    Serial.println("IV decoded: ");
//    aes.printArray( (byte *)iv_decoded, 16 );
    
    // Decrypt data
    aes.do_aes_decrypt((byte *)data_decoded, encrypted_length, out, key, 128, (byte *)p_iv);

    char message[100];
    b64_decode(message, (char *)out, aes.get_size());

    Serial.print("Received Message: ");
    Serial.println(message);
    Serial.println("");
}

// Send sample data
void    sendData() {
    initSession();          // Generate a new set of keys

    // We derive now the AES128 key from the shared key.
    // This is one of the simplest ways, just to take the initial 16 bytes.
    // One could also use the remaining 16 bit as the IV, but that would reveal half of the shared key.
    // Another way is to make a SHA256 of the shared key and get the key and IV from that output or
    // use other key derivation functions.
    memcpy( key , m_shkey , 16 );   // Encrypt using the negociated key
    printHex("AES128 key to be used: ", key , 16 );

    String data = String( counter++ );
    encryptData("{\"testdata\": \"" + data + "\"}");
}

// Connects to WIFI
void    WIFI_Connect() {
    int i=0;
    // Connect to WiFi network
    Serial.println();
    Serial.println();
    Serial.printf("Connecting to WIFI: %s\n", SSID.c_str());
    
    WiFi.mode(WIFI_STA);
    WiFi.begin( SSID , PASS);

    while (WiFi.status() != WL_CONNECTED) {
        delay(100);
        Serial.print(".");
        i++;
        if ( i > 15 ) {
            i = 0;                
            Serial.printf("\nConnecting to WIFI: %s\n", SSID.c_str());
        }
    }

    Serial.println("");
    Serial.println("WiFi connected");

    // Start the server
    server.begin();
    
    // Print the IP address
    Serial.print("Use this URL : ");
    Serial.print("http://");
    Serial.print(WiFi.localIP());
    Serial.println("/");
}

// Startup
void setup() {
    Serial.begin(115200);
    delay( 1000 );                              // To allow the serial monitor to pick up the port initial output
    
    aes.set_key( key , sizeof(key));            // Get the globally defined key for encryption
    aesDecript.set_key( key , sizeof(key));     // Get the globally defined key for decryption
    
    // Connect to WIFI.
    WIFI_Connect();
        
    sendData() ;                                // Initial send data, and then
    timer.setInterval( 10000 , sendData );      // Sends data every 10s

    // Generate the session
    //initSession();
    //timer.setInterval( 10000 , initSession );

}

void loop() { 

   timer.run();                                 // Execute timer events

    // Check for an active client
    WiFiClient client = server.available();
     
    if (!client) {
        return;
    } 
          
    while(!client.available()){  
      delay(1);
      timer.run(); 
    }     
  
    // Read client request
    String request = client.readStringUntil('\r');
    
    client.flush();
    if (request.indexOf("/info") != -1){  // OK
        String parse = getValue(request, '?', 1);
        String data = getValue(parse, '&', 0);
        String ivHttp = getValue(parse, '&', 1);
        String iv = getValue(ivHttp, ' ', 0);
        
        Serial.println("------------------- Data received --------------------");
        Serial.print(" Data: ");
        Serial.println(data);
        Serial.print(" IV: ");
        Serial.println( iv);
        
        decryptData(data, iv);
    }
}
