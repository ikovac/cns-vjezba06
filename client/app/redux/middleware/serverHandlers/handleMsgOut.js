// Info: config is an alias to "config/default.json" file
// (the alias is set in webpack.config.js).
import { Constants } from "config";

import serverAPI from "app/services/server-api/ServerAPI.js";
import { msgSent } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";

import CryptoProvider from 'app/services/security/CryptoProvider.js';
const crypto = require('crypto');

const { MsgType } = Constants;

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { wrapped }
  } = action;
  if (wrapped) return next(action);

  const {
    client: { nickname, id },
    credentials
  } = getState();

  //===================================================
  // Try to load an encryption key for this client id
  //===================================================
  const key = loadKey(id, credentials);

  //===================================================
  // If the encryption key is successfully loaded,
  // it is implied that all outgoing messages from this
  // client will be encrypted with that key.
  //===================================================

  let encryptedContent = undefined;
  let encrypt_key = undefined;
  let hmac_key = undefined;
  let hmac = undefined;
  if(key) {
    encrypt_key = key.slice(0,32);
    hmac_key = key.slice(32);

    hmac = crypto.createHmac('sha256', hmac_key);
    
    encryptedContent = CryptoProvider.encrypt('CBC', {key: encrypt_key, plaintext: action.payload, iv: crypto.randomBytes(16)});
  }

  const msg = {
    type: MsgType.BROADCAST,
    id,
    nickname,
    timestamp: Date.now(),
    content: encryptedContent ? encryptedContent.ciphertext : action.payload,
    iv: encryptedContent ? encryptedContent.iv : undefined
  };

  if(key) {
    const serializedMsg = JSON.stringify(msg);
    hmac.update(serializedMsg);
    const authTag = hmac.digest().slice(0, 16);
    msg.authTag = authTag;
  }

  serverAPI.send(msg).then(dispatch(msgSent(msg)));
};
