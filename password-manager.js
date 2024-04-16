"use strict";

const { randomBytes } = require("crypto");
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */

  constructor(masterKey, hmacKey, masterSalt, hmacSalt, iv, kvs, version) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      masterSalt: masterSalt,
      hmacSalt: hmacSalt,
      iv: iv,
      version: version,
      kvs: kvs
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      masterKey: masterKey,
      hmacKey: hmacKey
    };

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
    let version = "CS 255 Password Manager v1.0";

    let kvs = {};
    
    let passwordBuffer = stringToBuffer(password);

    let masterSalt = randomBytes(16);
    let masterSaltB64 = encodeBuffer(masterSalt);
    let hmacSalt = randomBytes(16);
    let hmacSaltB64 = encodeBuffer(hmacSalt);

    let iv = randomBytes(16);
    let ivB64 = encodeBuffer(iv);
    
    let pbkdf2Key = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);

    // Key for encrypting password
    let masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      pbkdf2Key,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    let exportedMasterKey = await subtle.exportKey("raw", masterKey);
    let exportedMasterKeyB64 = encodeBuffer(exportedMasterKey);

    // Key for verifying domain
    let HMACKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      pbkdf2Key,
      { name: "HMAC", hash: {name: "SHA-256"}, length: 256 },
      true,
      ["sign", "verify"]
    );
    let exportedHMACKey = await subtle.exportKey("raw", HMACKey);
    let exportedHMACKeyB64 = encodeBuffer(exportedHMACKey);

    let keychain = new Keychain(exportedMasterKeyB64, exportedHMACKeyB64, masterSaltB64, hmacSaltB64, ivB64, kvs, version);

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
    throw "Not Implemented!";
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
    let encodedStore = JSON.stringify(this);
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }

// These code is for testing
async function test(password){
  // initialize keychain
  let keychain = await Keychain.init(password);
  let data = await keychain.dump();
  console.log(data);
  
  // test for encryption & decryption
  let pwd = "testaaaaaaa";
  let keychain_restored = JSON.parse(data[0]);
  
  let exportedMasterKeyB64 = keychain_restored.secrets.masterKey;
  let exportedMasterKey = decodeBuffer(exportedMasterKeyB64);

  let ivB64 = keychain_restored.data.iv;
  let iv = decodeBuffer(ivB64);

  // encrypt pwd
  let masterKey = await subtle.importKey(
    "raw",
    exportedMasterKey,
    {name: "AES-GCM", hash: {name: "SHA-256"}},
    true,
    ["encrypt", "decrypt"]
  );

  // decrypt pwd
  let encryptedPwd = await subtle.encrypt(
    { name: "AES-GCM", iv },
    masterKey, 
    stringToBuffer(pwd)
  );
  console.log(encodeBuffer(encryptedPwd));

  let decryptedPwd = await subtle.decrypt(
    { name: "AES-GCM", iv },
    masterKey,
    encryptedPwd
  )

  console.log(bufferToString(decryptedPwd))
  // subtle.verify("SHA-256", )
}
let password = "This is the password";
test(password);

