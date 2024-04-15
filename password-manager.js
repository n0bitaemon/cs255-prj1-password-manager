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

  constructor(_version, _masterKey, _masterSalt) {
    this.data = {
      version: _version
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      masterKey: _masterKey,
      masterSalt: _masterSalt
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
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

    let passwordBuffer = stringToBuffer(password);
    let masterSalt = randomBytes(128);
    let masterKey = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);

    return new this(version, masterKey, masterSalt);

    // let derivedKey = await subtle.deriveKey(
    //   { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, 
    //   masterKey, 
    //   { name: "AES-GCM", length: 256 },
    //   false,
    //   ["encrypt", "decrypt"]
    // );
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

// module.exports = { Keychain }

// These code is for testing
async function test(password){
  let keychain = await Keychain.init(password);
  let data = await keychain.dump();
  
  console.log(data[1])
  let checksum = await subtle.digest("SHA-256", stringToBuffer(data[0]));
  
  if(encodeBuffer(checksum) === data[1]){
    console.log("MATCH")
  }else{
    console.log("UNMATCH")
  }
  // subtle.verify("SHA-256", )
}
let password = "This is the password";
test(password);

