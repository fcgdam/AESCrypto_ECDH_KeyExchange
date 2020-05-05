// NodeJs simple DH key exchange using Ecliptic curves with the Curve25519
//
const curve = require('curve25519-n');

// Generate random 32 bytes secret
function randomSecret() {
   var result           = '';
   var characters       = 'ABCDEFGHIJKLMNOPQRSTUVXZabcdefghijklmnopqrstuvxz0123456789';
   var charactersLength = characters.length;
   for ( var i = 0; i < 32; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   //console.log( result );
   return result;
}


// Generate the cryptographic material
var aliceServerSecret = Buffer.from( randomSecret() ); 
    
var alicePrivateKey = curve.makeSecretKey( aliceServerSecret );
var alicePublicKey  = curve.derivePublicKey( alicePrivateKey );
    
var bobServerSecret = Buffer.from( randomSecret() ); 
    
var bobPrivateKey = curve.makeSecretKey( bobServerSecret );
var bobPublicKey  = curve.derivePublicKey( bobPrivateKey );

var alice_shkey = curve.deriveSharedSecret(  alicePrivateKey , bobPublicKey );
var bob_shkey   = curve.deriveSharedSecret(  bobPrivateKey , alicePublicKey );

console.log("Alice public key: " ,  Buffer.from( alicePublicKey).toString('hex') );
console.log("Bob public key:   " ,  Buffer.from( bobPublicKey).toString('hex') );
console.log("");
console.log("------ Calculated shared keys: ");
console.log("Alice shared key: ", Buffer.from(alice_shkey).toString('hex') );
console.log("Bob shared key:   ",  Buffer.from(bob_shkey).toString('hex') );
