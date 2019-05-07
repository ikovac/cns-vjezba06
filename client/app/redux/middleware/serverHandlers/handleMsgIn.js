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
    if(key) {
      /* console.log("MSG IS");
      console.log(msg); */
      const {iv, content: ciphertext, tag} = msg;
      console.log("IV: ", iv);
      console.log("Ciphertext: ", ciphertext);
      console.log("TAG: ", tag);
      let msgContent = iv + ciphertext + tag;
      console.log("msgContent: ", msgContent);

      try {
        msg.content = CryptoProvider.decrypt('GCM', {key, msgContent});
      } catch(err) {
        console.log(err);
      }
    }
  }

  dispatch(serverMsg(msg));
};
