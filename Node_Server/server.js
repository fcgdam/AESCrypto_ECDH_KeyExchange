// NodeJs Backend server for receiving AES128 Encrypted data
//
// Version: 1.0.0 - Initial code
// Version: 1.1.0 - Use Diffie-Hellmann Key Agreement protocol using Eliptic Curve Cryptography: EC25519
//
var SERVERPORT    = process.env.SERVEPORT || 8087;

// The AES encryption/decription key to be used.
var AESKey = '2B7E151628AED2A6ABF7158809CF4F3C';                        // This is a pre-shared key

// Define and call the packages necessary for the building the REST API.
const express       = require('express');
const app	        = express();
const bodyParser    = require('body-parser');
const cors          = require('cors')
const morgan        = require('morgan');
const CryptoJS      = require('crypto-js');

const curve = require('curve25519-n');
var serverSecret = Buffer.from( randomSecret() );       // To initialize a server random secret

var ecdhPrivateKey = curve.makeSecretKey( serverSecret );       // Generate the private key
var ecdhPublicKey  = curve.derivePublicKey( ecdhPrivateKey );   // Generate the public key derived from the private key.

//Configure Express
app.use( bodyParser.urlencoded({ extended: true }) );
app.use( bodyParser.json() );
app.use( cors() );
app.options( '*', cors() );
app.use( morgan('dev') );

var router = express.Router();

// Generate random 32 bytes secret
function randomSecret() {
   var result           = '';
   var characters       = 'ABCDEFGHIJKLMNOPQRSTUVXZabcdefghijklmnopqrstuvxz0123456789';
   var charactersLength = characters.length;
   for ( var i = 0; i < 32; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }   
   console.log( result );
   return result;
}

//==============================================================================
function    decryptData( data, IV ) {
    var plain_iv = Buffer.from( IV , 'base64').toString('hex');
    var iv       = CryptoJS.enc.Hex.parse( plain_iv );
    var key      = CryptoJS.enc.Hex.parse( AESKey );

    // Decrypt
    var bytes = CryptoJS.AES.decrypt( data, key , { iv: iv} )

    try {
        var plaintext = bytes.toString(CryptoJS.enc.Base64)
        var decoded_b64msg = Buffer.from(plaintext , 'base64').toString('ascii');
        var decoded_msg = Buffer.from( decoded_b64msg , 'base64').toString('ascii');
        console.log("Decrypted message: ", decoded_msg);
    } catch(error) {
        console.log("Decryption error: " + error)
    }
}

//==============================================================================
function    ProcessData( req , res ) {
    
    console.log( "Data request: " , req.body );
    
    decryptData( req.body.data, req.body.iv );
    
    return res.status(200).json({success:true, message: 'success.' });
}    

//==============================================================================
// Received the foreign (other peer) DH public key and generates the shared key
function    GetSession( req , res ) {
    //console.log("-----------------------------------------------------------------------");
    //console.log( "Data request: " , req.body );

    var f_pubkey = req.body.pubkey;                             // The other party DH public key
    var fpubk = Buffer.from( f_pubkey, 'hex');                  // Move to buffer

    console.log("Foreign Public Key: ",  f_pubkey );

    var shkey = curve.deriveSharedSecret( ecdhPrivateKey , fpubk );    
    console.log( "Shared key: " ,  Buffer.from(shkey).toString('hex') );

    // Set the decrypt key equal to the shared key
    AESKey = Buffer.from(shkey).toString('hex').substring(0,32);  // Only use the first 16 bytes for AES128
    console.log("AES128 key to be used: " , AESKey );
    
    var pub_key = Buffer.from( ecdhPublicKey ).toString('hex');

    return res.status(200).json({pubkey:pub_key});
}

// This REST end points here are NOT authenticated.
// The entry point is always through /auth first for users.
router.route('/setdata')
    .post( ProcessData )                  // Validate the user 
    .get( function(req, res) {
       console.log("Not implemented");
       return res.status(403).json({success: false, message: 'Not permited.' });
    });

router.route('/getsession')
    .post( GetSession );


router.route('/')
    .get( function(req, res) {
        res.status(200).json({ info: 'Backend REST Server' });
    });


// Generate the cryptographic material
var serverSecret = Buffer.from( randomSecret() ); 
    
var ecdhPrivateKey = curve.makeSecretKey( serverSecret );
var ecdhPublicKey  = curve.derivePublicKey( ecdhPrivateKey );
    
var serverSecret1 = Buffer.from( randomSecret() ); 
    
var ecdhPrivateKey1 = curve.makeSecretKey( serverSecret1 );
var ecdhPublicKey1  = curve.derivePublicKey( ecdhPrivateKey1 );

var shkey = curve.deriveSharedSecret( ecdhPrivateKey , ecdhPublicKey1 );
var shkey1 = curve.deriveSharedSecret( ecdhPrivateKey1 , ecdhPublicKey );

console.log( Buffer.from(ecdhPublicKey).toString('hex') );
console.log( Buffer.from(shkey).toString('hex') );
console.log( Buffer.from(shkey1).toString('hex') );
//==============================================================================
// Start the server
// Our base url is /
app.use('/', router);
app.listen( SERVERPORT );

var datenow = new Date();
console.log("=========== ESP8266 - REST Api Server =============================");
console.log("Server started at " + datenow );
console.log("Api endpoint available at server port: " + SERVERPORT );
