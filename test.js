const { isoBase64URL } = require('@simplewebauthn/server/helpers');

// Example base64URL string (like the one you'd get from WebAuthn)
const base64URLString = 'pQECAyYgASFYIH8VUgyuZAc6FVHSUtf2nsJGSEXPP0BE7Z3HHkEJaQElIlggdULsd6xRxfTHbceVsCobnmyNlbajcHmy3zWXN1yPH6s';

// Convert base64URL-encoded string to Buffer (or Uint8Array)
const decodedBuffer = isoBase64URL.toBuffer(base64URLString);

console.log(decodedBuffer);

// Convert Buffer or Uint8Array back to base64URL string
const encodedBase64URL = isoBase64URL.fromBuffer(decodedBuffer);

console.log(encodedBase64URL);
