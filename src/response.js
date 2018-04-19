const regex = /^([A-Za-z0-9-_=]*)\.([A-Za-z0-9-_=]*)\.([A-Za-z0-9-_+/=]*)$/g;
const base64url = require('base64url');
const ethutil = require('ethereumjs-util');
const Web3 = require('web3');
const { utils } = new Web3()._extend;

const ABI = [{"constant":true,"inputs":[{"name":"_key","type":"bytes32"}],"name":"getKeyPurpose","outputs":[{"name":"","type":"uint256[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_key","type":"bytes32"},{"name":"_purpose","type":"uint256"}],"name":"getKey","outputs":[{"name":"purpose","type":"uint256"},{"name":"kType","type":"uint256"},{"name":"key","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_key","type":"bytes32"},{"name":"_purpose","type":"uint256"},{"name":"_type","type":"uint256"}],"name":"addKey","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_claimType","type":"uint256"}],"name":"getClaimIdsByType","outputs":[{"name":"claimIds","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_claimId","type":"bytes32"}],"name":"removeClaim","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_key","type":"bytes32"},{"name":"_purpose","type":"uint256"}],"name":"removeKey","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"uint256"},{"name":"_approve","type":"bool"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_purpose","type":"uint256"}],"name":"getKeysByPurpose","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_claimType","type":"uint256"},{"name":"_scheme","type":"uint256"},{"name":"_issuer","type":"address"},{"name":"_signature","type":"bytes"},{"name":"_data","type":"bytes"},{"name":"_uri","type":"string"}],"name":"addClaim","outputs":[{"name":"requestId","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"},{"name":"_data","type":"bytes"}],"name":"execute","outputs":[{"name":"executionId","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_claimId","type":"bytes32"}],"name":"getClaim","outputs":[{"name":"claimType","type":"uint256"},{"name":"scheme","type":"uint256"},{"name":"issuer","type":"address"},{"name":"signature","type":"bytes"},{"name":"data","type":"bytes"},{"name":"uri","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"key","type":"bytes32"}],"name":"Debug","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"claimRequestId","type":"uint256"},{"indexed":true,"name":"claimType","type":"uint256"},{"indexed":false,"name":"scheme","type":"uint256"},{"indexed":true,"name":"issuer","type":"address"},{"indexed":false,"name":"signature","type":"bytes"},{"indexed":false,"name":"data","type":"bytes"},{"indexed":false,"name":"uri","type":"string"}],"name":"ClaimRequested","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"claimId","type":"bytes32"},{"indexed":true,"name":"claimType","type":"uint256"},{"indexed":false,"name":"scheme","type":"uint256"},{"indexed":true,"name":"issuer","type":"address"},{"indexed":false,"name":"signature","type":"bytes"},{"indexed":false,"name":"data","type":"bytes"},{"indexed":false,"name":"uri","type":"string"}],"name":"ClaimAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"claimId","type":"bytes32"},{"indexed":true,"name":"claimType","type":"uint256"},{"indexed":false,"name":"scheme","type":"uint256"},{"indexed":true,"name":"issuer","type":"address"},{"indexed":false,"name":"signature","type":"bytes"},{"indexed":false,"name":"data","type":"bytes"},{"indexed":false,"name":"uri","type":"string"}],"name":"ClaimRemoved","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"claimId","type":"bytes32"},{"indexed":true,"name":"claimType","type":"uint256"},{"indexed":false,"name":"scheme","type":"uint256"},{"indexed":true,"name":"issuer","type":"address"},{"indexed":false,"name":"signature","type":"bytes"},{"indexed":false,"name":"data","type":"bytes"},{"indexed":false,"name":"uri","type":"string"}],"name":"ClaimChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"key","type":"bytes32"},{"indexed":true,"name":"purpose","type":"uint256"},{"indexed":true,"name":"kType","type":"uint256"}],"name":"KeyAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"key","type":"bytes32"},{"indexed":true,"name":"purpose","type":"uint256"},{"indexed":true,"name":"kType","type":"uint256"}],"name":"KeyRemoved","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"executionId","type":"uint256"},{"indexed":true,"name":"to","type":"address"},{"indexed":true,"name":"value","type":"uint256"},{"indexed":false,"name":"data","type":"bytes"}],"name":"ExecutionRequested","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"executionId","type":"uint256"},{"indexed":true,"name":"to","type":"address"},{"indexed":true,"name":"value","type":"uint256"},{"indexed":false,"name":"data","type":"bytes"}],"name":"Executed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"executionId","type":"uint256"},{"indexed":false,"name":"approved","type":"bool"}],"name":"Approved","type":"event"}];
const ACTION_KEY_PURPOSE = 2;

const LoginResponse = (web3provider) => {

  const web3 = new Web3(new Web3.providers.HttpProvider(web3provider));

  const addressToKey = address => `0x${utils.padLeft(address.substring(2), 64)}`;

  const isActionKey = (identity, keyAddress, cb) => {
    const contract = web3.eth.contract(ABI).at(identity);
    contract.getKeyPurpose(addressToKey(keyAddress), (err, res) => {
      if(err) return cb(err);
      if(!res || res.length === 0) return cb(null, false);
      const exists = res.map(purpose => purpose.toNumber()).find(purpose => purpose === ACTION_KEY_PURPOSE);
      return cb(null, !!exists);
    });
  };

  const decodeToken = (token, maxDurationInSeconds = null) => {
    if(!token) return {
      success: false,
      error: 'No token'
    };
    const parsed = regex.exec(token);
    if(!parsed || parsed.length != 4) return {
      success: false,
      error: 'Invalid token format'
    };
    const [_, encHeader, encPayload, encSignature] = parsed;
    let header, payload = null;
    try {
      header = JSON.parse(base64url.decode(encHeader));
      payload = JSON.parse(base64url.decode(encPayload));
    }
    catch (e) {
      return {
        success: false,
        error: 'Invalid token encoding'
      };
    }
    if(!header || !header.alg)
      return {
        success: false,
        error: 'Invalid header'
      };
    if(header.alg !== 'ESK256')
      return {
        success: false,
        error: `Signature alg ${header.alg} is not supported`
      };
    if(!payload || !payload.sub || !payload.aud || !payload.iat)
      return {
        success: false,
        error: 'Invalid payload'
      };
    if(maxDurationInSeconds) {
      const now = Math.floor(Date.now() / 1000);
      if(now - payload.iat > maxDurationInSeconds) {
        return {
          success: false,
          error: `Token is expired (iat = ${payload.iat})`
        };
      }
    }
    return {
      success: true,
      rawHeader: encHeader,
      rawPayload: encPayload,
      rawSignature: encSignature,
      header,
      payload
    };
  };

  const validateSignature = (decoded) => {
    if(!decoded.success) return decoded;
    try {
      const decodedSignature = Buffer.from(base64url.toBase64(decoded.rawSignature), 'base64');
      const msg = Buffer.from(`${decoded.rawHeader}.${decoded.rawPayload}`, 'utf8');
      const hash = ethutil.hashPersonalMessage(msg);  
      const sigParams = ethutil.fromRpcSig(decodedSignature);
      const signerPublicKey = ethutil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
      const signerAddress = `0x${ethutil.publicToAddress(signerPublicKey).toString('hex')}`;
      if(!signerAddress)
        return {
          ...decoded,
          success: false,
          error: 'Invalid signature'
        };
      return {
        success: true,
        ...decoded,
        signer: signerAddress
      };
    }
    catch (e) {
      return {
        ...decoded,
        success: false,
        error: 'Invalid signature'
      };
    }  
  };

  return (token, spIdentity, maxDurationInSeconds, cb) => {
    const result = validateSignature(decodeToken(token, maxDurationInSeconds));
    if(!result.success) return cb(result.error);
    if(spIdentity && result.payload.aud !== spIdentity)
      return cb(`Invalid aud (${result.payload.aud} is not ${spIdentity})`);
    isActionKey(result.payload.sub, result.signer, (err, isSuccess) => {
      if(err) return cb('Cannot call Identity contract to validate');
      if(!isSuccess) return cb('Signing key is not registered on identity contract as ACTION key');
      return cb(null, result);
    });    
  };
  
};

module.exports = LoginResponse;