import { serverMsg } from "app/redux/actions/serverActions.js";
import { JSONparse } from "app/utils/safeJSON.js";
import { clientError } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";

import CryptoProvider from 'app/services/security/CryptoProvider.js';
const crypto = require('crypto');

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { serialized }
  } = action;
  if (!serialized) return next(action);

  let msg = JSONparse(action.payload);

  if (Object.is(msg, undefined)) {
    return dispatch(clientError(`JSON.parse error: ${data}`));
  }

  if (msg.id) {
    const { credentials } = getState();

    //===================================================
    // Try to load an encryption key for this client id;
    // please note that this is a remote client.
    //===================================================
    const key = loadKey(msg.id, credentials);

    //===================================================
    // If the encryption key is successfully loaded,
    // it is implied that all incoming messages from this
    // remote client will be encrypted with that key.
    // So, we decrypt the messages before reading them.
    //===================================================
    let encrypt_key = undefined;
    let hmac_key = undefined;
    let hmac = undefined;
    if(key) {
      encrypt_key = key.slice(0,32);
      hmac_key = key.slice(32);

      hmac = crypto.createHmac('sha256', hmac_key);
      
      let recived_msg = {... msg};
      // recived_msg.timestamp = Date.now();
      delete recived_msg.authTag;

      const serializedMsg = JSON.stringify(recived_msg);
      hmac.update(serializedMsg);
      const authTag = hmac.digest().slice(0, 16);

      if(!crypto.timingSafeEqual(Buffer.from(msg.authTag.data), authTag)) {
        msg.content = 'AUTHENTICATION FAILURE';
        dispatch(serverMsg(msg));
        return;
      }

      msg.content = CryptoProvider.decrypt('CBC', {key: encrypt_key, ciphertext: msg.content, iv: Buffer.from(msg.iv, 'hex')}).plaintext;
    }
  }

  dispatch(serverMsg(msg));
};
