const { isoBase64URL } = require('@simplewebauthn/server/helpers');

// Example base64URL string (like the one you'd get from WebAuthn)
const base64URLString = 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdocGMybHpkMlZpWVhWMGFHNWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0';

// Convert base64URL-encoded string to Buffer (or Uint8Array)
const decodedBuffer = isoBase64URL.toBuffer(base64URLString);

console.log(decodedBuffer);


// Convert Buffer or Uint8Array back to base64URL string
const encodedBase64URL = isoBase64URL.fromBuffer(decodedBuffer);

console.log(encodedBase64URL);
