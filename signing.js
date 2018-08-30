'use strict';

const secp256k1 = require('secp256k1');
const { randomBytes, createHash } = require('crypto');


/**
 * A function which generates a new random Secp256k1 private key, returning
 * it as a 64 character hexadecimal string.
 *
 * Example:
 *   const privateKey = createPrivateKey();
 *   console.log(privateKey);
 *   // 'e291df3eede7f0c520fddbe5e9e53434ff7ef3c0894ed9d9cbcb6596f1cfe87e'
 */
const createPrivateKey = () => {

  /*
  // generate message to sign
  const msg = randomBytes(32)

  // generate privKey
  let privKey
  do {
    privKey = randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privKey))

  // get the public key in a compressed format
  const pubKey = secp256k1.publicKeyCreate(privKey)
  console.log(privKey);
  console.log(pubKey);
  console.log(pubKey);
  // sign the message
  const sigObj = secp256k1.sign(msg, privKey)

  // verify the signature
  console.log(secp256k1.verify(msg, sigObj.signature, pubKey))
  // => true
  return privKey.toString;

*/
  // generate message to sign
  const msg = randomBytes(32)

  // generate privKey
  let privKey
  do {
    privKey = randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privKey))
  return privKey.toString('hex');
};

/**
 * A function which takes a hexadecimal private key and returns its public pair
 * as a 66 character hexadecimal string.
 *
 * Example:
 *   const publicKey = getPublicKey(privateKey);
 *   console.log(publicKey);
 *   // '0202694593ddc71061e622222ed400f5373cfa7ea607ce106cca3f039b0f9a0123'
 *
 * Hint:
 *   Remember that the secp256k1-node library expects raw bytes (i.e Buffers),
 *   not hex strings! You'll have to convert the private key.
 */
const getPublicKey = privateKey => {
  // get the public key in a compressed format
  let pubKey = secp256k1.publicKeyCreate(Buffer.from(privateKey,'hex'));
  return pubKey.toString('hex');
};

/**
 * A function which takes a hex private key and a string message, returning
 * a 128 character hexadecimal signature.
 *
 * Example:
 *   const signature = sign(privateKey, 'Hello World!');
 *   console.log(signature);
 *   // '4ae1f0b20382ad628804a5a66e09cc6bdf2c83fa64f8017e98d84cc75a1a71b52...'
 *
 * Hint:
 *   Remember that you need to sign a SHA-256 hash of the message,
 *   not the message itself!
 */
const sign = (privateKey, message) => {
  // let sha256 = message => createHash('sha256').update(Buffer.from(message,'hex')).digest();
  // return secp256k1.sign(Buffer.from(sha256,'hex'), Buffer.from(privateKey,'hex'));

  //console.log(message)
  let hash = createHash('sha256');
  if (message) {
    //console.log('true');
    hash.update(Buffer.from(message));
    //console.log(hash.digest('hex'))
  } else {
    console.log('Error')
  }
  //console.log('Before')
  let msg = Buffer.from(hash.digest('hex'), 'hex')
  //hash.update(privateKey)
  let privKey = Buffer.from(privateKey, 'hex')
  let sigObj = secp256k1.sign(msg, privKey)
  //console.log('After')
  //console.log(sigObj);
  //console.log(sigObj.signature);
  //console.log(sigObj.signature.toString('hex'));
  
  //const buf2 = Buffer.toString(sigObj, 'hex')

  return sigObj.signature.toString('hex');
};

/**
 * A function which takes a hex public key, a string message, and a hex
 * signature, and returns either true or false.
 *
 * Example:
 *   console.log( verify(publicKey, 'Hello World!', signature) );
 *   // true
 *   console.log( verify(publicKey, 'Hello World?', signature) );
 *   // false
 */
const verify = (publicKey, message, signature) => {
  //console.log(message)
  let hash = createHash('sha256');
  if (message) {
    //console.log('true');
    hash.update(Buffer.from(message));
    //console.log(hash.digest('hex'))
  } else {
    console.log('Error')
  }
  //console.log('Before')
  let msg = Buffer.from(hash.digest('hex'), 'hex');
  let sig = Buffer.from(signature, 'hex');
  let pub = Buffer.from(publicKey, 'hex');

  return secp256k1.verify(msg, sig, pub);

};

module.exports = {
  createPrivateKey,
  getPublicKey,
  sign,
  verify
};
