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

  if(key) {
    encryptedContent = CryptoProvider.encrypt('GCM', {key, plaintext: action.payload, iv: crypto.randomBytes(12)});
  }

  const msg = {
    type: MsgType.BROADCAST,
    id,
    nickname,
    timestamp: Date.now(),
    content: encryptedContent ? encryptedContent.ciphertext : action.payload,
    iv: encryptedContent ? encryptedContent.iv : undefined,
    tag: encryptedContent ? encryptedContent.tag : undefined
  };

  serverAPI.send(msg).then(dispatch(msgSent(msg)));
};
