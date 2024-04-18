"use strict";

const { randomBytes } = require("crypto");
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const PADDED_PASSWORD_LENGTH = 72;

function pad(pwd, len){
  const paddingOne = Buffer.from([1]);
  const paddingZero = Buffer.from([0]);

  let paddedPwd = Buffer.concat([pwd, paddingOne]);
  while(paddedPwd.length < len){
    paddedPwd = Buffer.concat([paddedPwd, paddingZero]);
  }

  return paddedPwd;
}

function unpad(paddedPwd){
  let i = paddedPwd.length - 1;
  while(paddedPwd[i] == 0 && i >= 0){
    i--;
  }
  return paddedPwd.slice(0, i);
}

/********* Implementation ********/
class Keychain {

  ready = false;
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */

  constructor(kvs, masterSalt, HMACSalt, HMACKey_sig, HMACKey, AESGCMSalt, AESGCMKey_sig, AESGCMKey) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      kvs: kvs,
      masterSalt: masterSalt,
      HMACSalt: HMACSalt,
      HMACKey_sig: HMACKey_sig,
      HMACKey: HMACKey,
      AESGCMSalt: AESGCMSalt,
      AESGCMKey_sig: AESGCMKey_sig,
      AESGCMKey: AESGCMKey
    };

    this.ready = true;

    // throw "Not Implemented!";
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    let passwordBuffer = stringToBuffer(password);

    // let iv = randomBytes(16);
    // let ivB64 = encodeBuffer(iv);

    let rawKey = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);

    // Master key for load()
    let masterSalt = randomBytes(16);
    let masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );

    // AES-GCM key for password
    let AESGCMSalt = randomBytes(16);
    let AESGCMKey_sig = await subtle.sign(
      "HMAC",
      masterKey,
      AESGCMSalt
    )
    let AESGCMKey = await subtle.importKey(
      "raw",
      AESGCMKey_sig,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // HMAC key for domain name
    let HMACSalt = getRandomBytes(16);
    let HMACKey_sig = await subtle.sign(
      "HMAC",
      masterKey,
      HMACSalt
    )
    let HMACKey = await subtle.importKey(
      "raw",
      HMACKey_sig,
      { name: "HMAC", hash: { name: "SHA-256" }, length: 256 },
      true,
      ["sign"]
    );

    let keychain = new Keychain({}, masterSalt, HMACSalt, HMACKey_sig, HMACKey, AESGCMSalt, AESGCMKey_sig, AESGCMKey);

    return keychain;
    // throw "Not Implemented!";
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if(trustedDataCheck !== undefined){
      let checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
      if(encodeBuffer(checksum) !== trustedDataCheck){
        throw "Tampering is detected!";
      }
    }

    let contents = JSON.parse(repr);

    let masterSalt = decodeBuffer(contents["masterSalt"]);
    let HMACSalt = decodeBuffer(contents["HMACSalt"]);
    let HMACKey_sig = decodeBuffer(contents["HMACKey_sig"]);
    let AESGCMSalt = decodeBuffer(contents["AESGCMSalt"]);
    let AESGCMKey_sig = decodeBuffer(contents["AESGCMKey_sig"]);

    // authentication
    let rawKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    let masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );

    let HMACVerification = await subtle.verify(
      "HMAC",
      masterKey,
      HMACKey_sig,
      HMACSalt
    )

    let AESGCMVerification = await subtle.verify(
      "HMAC",
      masterKey,
      AESGCMKey_sig,
      AESGCMSalt
    );

    // For avoiding timing attack
    if(AESGCMVerification !== true || HMACVerification !== true){
      throw "Password is incorect!";
    }

    let HMACKey = await subtle.importKey(
      "raw",
      HMACKey_sig,
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign"]
    );

    let AESGCMKey = await subtle.importKey(
      "raw",
      AESGCMKey_sig,
      {name: "AES-GCM", length: 256},
      true,
      ["encrypt", "decrypt"]
    );
    
    let kvs = {}
    for(const [key, value] of Object.entries(contents["kvs"])){
      kvs[key] = {};
      kvs[key]["iv"] = decodeBuffer(value["iv"]);
      kvs[key]["pwd"] = decodeBuffer(value["pwd"]);
      kvs[key]["tag"] = decodeBuffer(value["tag"]);
    }
    
    return new Keychain(kvs, masterSalt, HMACSalt, HMACKey_sig, HMACKey, AESGCMSalt, AESGCMKey_sig, AESGCMKey);
    // throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    if(this.ready === false) throw "Keychain not initialized.";

    let contents = this.secrets;

    contents["masterSalt"] = encodeBuffer(contents["masterSalt"]);

    contents["HMACSalt"] = encodeBuffer(contents["HMACSalt"]);
    contents["HMACKey_sig"] = encodeBuffer(contents["HMACKey_sig"]);
    contents["HMACKey"] = encodeBuffer(await subtle.exportKey("raw", contents["HMACKey"]));

    contents["AESGCMSalt"] = encodeBuffer(contents["AESGCMSalt"]);
    contents["AESGCMKey_sig"] = encodeBuffer(contents["AESGCMKey_sig"]);
    contents["AESGCMKey"] = encodeBuffer(await subtle.exportKey("raw", contents["AESGCMKey"]));
    
    for(const [key, value] of Object.entries(contents["kvs"])){
      contents["kvs"][key]["iv"] = encodeBuffer(value["iv"]);
      contents["kvs"][key]["pwd"] = encodeBuffer(value["pwd"]);
      contents["kvs"][key]["tag"] = encodeBuffer(value["tag"]);
    }

    let encodedStore = JSON.stringify(contents);
    let checksum = await subtle.digest("SHA-256", stringToBuffer(encodedStore));
    checksum = encodeBuffer(checksum);

    return [encodedStore, checksum];
    // throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if(this.ready === false) throw "Keychain is not initialized.";
    
    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACKey,
      stringToBuffer(name)
    );

    let HMACKeyForTag = await subtle.importKey(
      "raw",
      key,
      {name: "HMAC", hash: "SHA-256"},
      false,
      ["verify"]
    );

    let plaintext = null;
    key = encodeBuffer(key);
    if(this.secrets.kvs.hasOwnProperty(key)){
      let value = this.secrets.kvs[key];
      let iv = value.iv;
      let encryptedPwd = value.pwd;
      let tag = value.tag;

      let verification = await subtle.verify(
        "HMAC",
        HMACKeyForTag,
        tag,
        encryptedPwd
      );
      
      if(verification === false) throw "Tampering is detected!";

      plaintext = await subtle.decrypt(
        {name: "AES-GCM", iv: iv},
        this.secrets.AESGCMKey,
        encryptedPwd
      );

      plaintext = bufferToString(unpad(Buffer.from(plaintext)));
    }

    return plaintext;
    // throw "Not Implemented!";
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if(this.ready === false) throw "Keychain not initialized.";

    // compute key for domain name
    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACKey,
      stringToBuffer(name)
    );

    let HMACKeyForTag = await subtle.importKey(
      "raw",
      key,
      {name: "HMAC", hash: "SHA-256"},
      false,
      ["sign"]
    );
    
    // encrypt the value
    let iv = randomBytes(16);
    let encryptedPwd = await subtle.encrypt(
      {name: "AES-GCM", iv: iv},
      this.secrets.AESGCMKey,
      pad(stringToBuffer(value), PADDED_PASSWORD_LENGTH)
    )

    let tag = await subtle.sign(
      "HMAC",
      HMACKeyForTag,
      encryptedPwd
    );

    this.secrets.kvs[encodeBuffer(key)] = {iv: iv, pwd: encryptedPwd, tag: tag};

    // throw "Not Implemented!";
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if(this.ready === false) throw "Keychain not initialized.";

    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACKey,
      stringToBuffer(name)
    );
    key = encodeBuffer(key);

    // Remove the entry from KVS
    if(this.secrets.kvs.hasOwnProperty(key)){
      delete this.secrets.kvs[key];
      return true;
    }

    return false;
    // throw "Not Implemented!";
  };
};

module.exports = { Keychain }
