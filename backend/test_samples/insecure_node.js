// Insecure Node.js sample — should trigger JS/TS negative rules.
const crypto = require('crypto');

function legacyHash(data) {
  return crypto.createHash('md5').update(data).digest('hex'); // weak-crypto
}

function legacySign() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

function legacyEcdsa() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
  });
  return { publicKey, privateKey };
}

async function webCryptoRsa() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048 },
    true,
    ['encrypt', 'decrypt'],
  );
  return keyPair;
}
