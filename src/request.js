const sha3 = require('crypto-js/sha3');
const secp256k1 = require('secp256k1');

const LoginRequest = (privateKey) => {
  
  /* Build the encoded payload to be signed */
  const buildContentToSign = (identityAddress, redirect, nonce) => {
    // Build the request
    const request = {
      identity: identityAddress,
      redirect,
      nonce
    };
    // Base64 encoded JSON
    return Buffer.from(
      JSON.stringify(request)
    ).toString('base64');
  };

  /* Compute a SHA3 hash for encoded payload */
  const hash = (encoded) => Buffer.from(
      sha3(encoded, { outputLength: 256 }).toString(),
      'hex'
    );
  
  /* Sign a hash with the private key */
  const signHash = (hash) => {
    const signature = secp256k1.sign(hash, privateKey);
    return {
      data: signature.signature.toString('base64'),
      recovery: signature.recovery
    };
  };

  /* Build a EDDITS LoginRequest */
  const buildLoginRequest = (encoded, signature) => {
    const loginRequest = {
      loginRequest: encoded,
      signature: JSON.stringify(signature)
    };
    return Buffer.from(
      JSON.stringify(loginRequest)
    ).toString('base64');
  };

  return (identityAddress, redirect, nonce) => {
      const toBeSigned = buildContentToSign(identityAddress, redirect, nonce);
      const signature = signHash(hash(toBeSigned));
      return buildLoginRequest(toBeSigned, signature);
  };
};

module.exports = LoginRequest;