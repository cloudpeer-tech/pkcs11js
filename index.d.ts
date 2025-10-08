// Type definitions for pkcs11js v1.1.2
// Project: https://github.com/PeculiarVentures/pkcs11js
// Definitions by: Stepan Miroshin <https://github.com/microshine>

/// <reference types="node" />

/**
 * A Node.js implementation of the PKCS#11 2.30 interface
 */
declare namespace pkcs11js {
    /**
     * PKCS#11 handle type
     */
    export type Handle = Buffer;

    /**
     * Structure that describes the version
     */
    export interface Version {
        /**
         * Major version number (the integer portion of the version)
         */
        major: number;
        /**
         * minor version number (the hundredths portion of the version)
         */
        minor: number;
    }

    /**
     * Provides general information about Cryptoki
     */
    export interface ModuleInfo {
        /**
         * Cryptoki interface version number, for compatibility with future revisions of this interface
         */
        cryptokiVersion: Version;
        /**
         * ID of the Cryptoki library manufacturer.
         * Must be padded with the blank character (' ').
         */
        manufacturerID: string;
        /**
         * Bit flags reserved for future versions. Must be zero for this version
         */
        flags: number;
        /**
         * Character-string description of the library.
         * Must be padded with the blank character (' ')
         */
        libraryDescription: string;
        /**
         * Cryptoki library version number
         */
        libraryVersion: Version;
    }

    /**
     * Provides information about a slot
     */
    export interface SlotInfo {
        /**
         * Character-string description of the slot.
         * Must be padded with the blank character (' ')
         */
        slotDescription: string;
        /**
         * ID of the slot manufacturer.
         * Must be padded with the blank character (' ')
         */
        manufacturerID: string;
        /**
         * Bits flags that provide capabilities of the slot
         */
        flags: number;
        /**
         * Version number of the slot's hardware
         */
        hardwareVersion: Version;
        /**
         * Version number of the slot's firmware
         */
        firmwareVersion: Version;
    }

    /**
     * Provides information about a token
     */
    export interface TokenInfo {
        /**
         * Application-defined label, assigned during token initialization.
         * Must be padded with the blank character (' ')
         */
        label: string;
        /**
         * ID of the device manufacturer. 
         * Must be padded with the blank character (' ')
         */
        manufacturerID: string;
        /**
         * Model of the device. 
         * Must be padded with the blank character (' ')
         */
        model: string;
        /**
         * Character-string serial number of the device. 
         * Must be padded with the blank character (' ')
         */
        serialNumber: string;
        /**
         * Bit flags indicating capabilities and status of the device
         */
        flags: number;
        /**
         * Maximum number of sessions that can be opened with the token at one time by a single application
         */
        maxSessionCount: number;
        /**
         * Number of sessions that this application currently has open with the token
         */
        sessionCount: number;
        /**
         * Maximum number of read/write sessions that can be opened with the token at one time by a single application
         */
        maxRwSessionCount: number;
        /**
         * Number of read/write sessions that this application currently has open with the token
         */
        rwSessionCount: number;
        /**
         * Maximum length in bytes of the PIN
         */
        maxPinLen: number;
        /**
         * Minimum length in bytes of the PIN
         */
        minPinLen: number;
        /**
         * version number of hardware
         */
        hardwareVersion: Version;
        /**
         * Version number of firmware
         */
        firmwareVersion: Version;
        /**
         * Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx 
         * (4 characters for the year; 2 characters each for the month, the day, the hour, the minute, 
         * and the second; and 2 additional reserved '0' characters). 
         * The value of this field only makes sense for tokens equipped with a clock, 
         * as indicated in the token information flags
         */
        utcTime: string;
        /**
         * The total amount of memory on the token in bytes in which public objects may be stored
         */
        totalPublicMemory: number;
        /**
         * The amount of free (unused) memory on the token in bytes for public objects
         */
        freePublicMemory: number;
        /**
         * The total amount of memory on the token in bytes in which private objects may be stored
         */
        totalPrivateMemory: number;
        /**
         * The amount of free (unused) memory on the token in bytes for private objects
         */
        freePrivateMemory: number;
    }

    /**
     * Provides information about a particular mechanism
     */
    export interface MechanismInfo {
        /**
         * The minimum size of the key for the mechanism
         */
        minKeySize: number;
        /**
         * The maximum size of the key for the mechanism
         */
        maxKeySize: number;
        /**
         * Bit flags specifying mechanism capabilities
         */
        flags: number;
    }

    /**
     * Provides information about a session
     */
    export interface SessionInfo {
        /**
         * ID of the slot that interfaces with the token
         */
        slotID: Buffer;
        /**
         * The state of the session
         */
        state: number;
        /**
         * Bit flags that define the type of session
         */
        flags: number;
        /**
         * An error code defined by the cryptographic device
         */
        deviceError: number;
    }

    export type Template = Attribute[];

    /**
     * A structure that includes the type and value of an attribute
     */
    export interface Attribute {
        /**
         * The attribute type
         */
        type: number;
        /**
         * The value of the attribute
         */
        value?: number | boolean | string | Buffer;
    }

    /**
     * A structure that specifies a particular mechanism and any parameters it requires
     */
    export interface Mechanism {
        /**
         * The type of mechanism
         */
        mechanism: number;
        /**
         * The parameter if required by the mechanism
         */
        parameter?: Buffer | IParams;
    }

    //#region Crypto parameters

    /**
     * A base structure of a parameter
     */
    export interface IParams {
        /**
         * Type of crypto param. Uses constants CK_PARAMS_*
         */
        type: number;
    }

    /**
     * A structure that provides the parameters for the {@link CKM_ECDH1_DERIVE} and {@link CKM_ECDH1_COFACTOR_DERIVE} 
     * key derivation mechanisms, where each party contributes one key pair
     */
    export interface ECDH1 extends IParams {
        /**
         * Key derivation function used on the shared secret value
         */
        kdf: number;
        /**
         * Some data shared between the two parties
         */
        sharedData?: Buffer;
        /**
         * The other party's EC public key
         */
        publicData: Buffer;
    }

    export interface AesCBC extends IParams {
        iv: Buffer;
        data?: Buffer;
    }

    export interface AesCCM extends IParams {
        dataLen: number;
        nonce?: Buffer;
        aad?: Buffer;
        macLen: number;
    }

    export interface AesGCM extends IParams {
        iv?: Buffer;
        aad?: Buffer;
        ivBits: number;
        tagBits: number;
    }

    export interface RsaOAEP extends IParams {
        hashAlg: number;
        mgf: number;
        source: number;
        sourceData?: Buffer;
    }

    export interface RsaPSS extends IParams {
        hashAlg: number;
        mgf: number;
        saltLen: number;
    }

    //#endregion

    export interface KeyPair {
        privateKey: Handle;
        publicKey: Handle;
    }

    export interface InitializationOptions {
        /**
         * NSS library parameters
         */
        libraryParameters?: string;
        /**
         * bit flags specifying options for {@link C_Initialize}
         * - CKF_LIBRARY_CANT_CREATE_OS_THREADS. True if application threads which are executing calls to the library
         *   may not use native operating system calls to spawn new threads; false if they may
         * - CKF_OS_LOCKING_OK. True if the library can use the native operation system threading model for locking;
         *   false otherwise
         */
        flags?: number;
    }

    /**
     * A Structure which contains a Cryptoki version and each function in the Cryptoki API
     */
    class PKCS11 {
        /**
         * Library path
         */
        public libPath: string;

        /**
         * Loads dynamic library with PKCS#11 interface
         * @param path The path to PKCS#11 library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public load(path: string): void;
        /**
         * Initializes the Cryptoki library
         * @param options Initialization options
         * Supports implementation of standard `CK_C_INITIALIZE_ARGS` and extended NSS format.
         * - if `options` is null or empty, it calls native `C_Initialize` with `NULL`
         * - if `options` doesn't have `libraryParameters`, it uses `CK_C_INITIALIZE_ARGS` structure
         * - if `options` has `libraryParameters`, it uses extended NSS structure
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Initialize(options?: InitializationOptions): void;
        /**
         * Closes dynamic library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public close(): void;
        /**
         * Indicates that an application is done with the Cryptoki library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Finalize(): void;
        /**
         * Returns general information about Cryptoki
         * @returns Information about Cryptoki
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetInfo(): ModuleInfo;

        //#region Slot and token management

        /**
         * Obtains a list of slots in the system
         * @param [tokenPresent] Only slots with tokens?
         * @returns Array of slot IDs
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSlotList(tokenPresent?: boolean): Handle[];
        /**
         * Obtains information about a particular slot in the system
         * @param  slot The ID of the slot
         * @returns Information about a slot
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSlotInfo(slot: Handle): SlotInfo;
        /**
         * Obtains information about a particular token in the system
         * @param slot ID of the token's slot
         * @returns Information about a token
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetTokenInfo(slot: Handle): TokenInfo;
        /**
         * Initializes a token
         * @param slot ID of the token's slot
         * @param [pin] The SO's initial PIN
         * @returns 32-byte token label (blank padded)
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_InitToken(slot: Handle, pin?: string, label?: string): string;
        /**
         * Initializes the normal user's PIN
         * @param session The session's handle
         * @param pin The normal user's PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_InitPIN(session: Handle, pin?: string): void;
        /**
         * Modifies the PIN of the user who is logged in
         * @param session The session's handle
         * @param oldPin The old PIN
         * @param newPin The new PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SetPIN(session: Handle, oldPin: string, newPin: string): void;
        /**
         * Obtains a list of mechanism types supported by a token
         * @param slot ID of token's slot
         * @returns A list of mechanism types
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetMechanismList(slot: Handle): number[];
        /**
         * Obtains information about a particular mechanism possibly supported by a token
         * @param slot ID of the token's slot
         * @param mech Type of mechanism
         * @returns Information about mechanism
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetMechanismInfo(slot: Handle, mech: number): MechanismInfo;

        //#endregion

        //#region Session management

        /**
         * Opens a session between an application and a token
         * @param slot The slot's ID
         * @param flags From CK_SESSION_INFO
         * @returns Session handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_OpenSession(slot: Handle, flags: number): Handle;
        /**
         * Closes a session between an application and a token
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CloseSession(session: Handle): void;
        /**
         * Closes all sessions with a token
         * @param slot The token's slot
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CloseAllSessions(slot: Handle): void;
        /**
         * Obtains information about the session
         * @param session The session's handle
         * @returns Receives session info
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSessionInfo(session: Handle): SessionInfo;
        /**
         * Logs a user into a token
         * @param session The session's handle
         * @param userType The user type
         * @param [pin] The user's PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Login(session: Handle, userType: number, pin?: string): void;
        /**
         * Logs a user out from a token
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Logout(session: Handle): void;

        //#endregion

        //#region Object management

        /**
         * Creates a new object
         * @param session The session's handle
         * @param template The object's template
         * @returns A new object's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CreateObject(session: Handle, template: Template): Handle;
        /**
         * Copies an object, creating a new object for the copy
         * @param session The session's handle
         * @param object The object's handle
         * @param template Template for new object
         * @returns A handle of copy
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CopyObject(session: Handle, object: Handle, template: Template): Handle;
        /**
         * Destroys an object
         * @param session The session's handle
         * @param object The object's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DestroyObject(session: Handle, object: Handle): void;
        /**
         * Gets the size of an object in bytes
         * @param session The session's handle
         * @param object The object's handle
         * @returns Size of an object in bytes
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetObjectSize(session: Handle, object: Handle): number;
        /**
         * Initializes a search for token and session objects that match a template
         * @param session The session's handle
         * @param template Attribute values to match
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjectsInit(session: Handle, template: Template): void;
        /**
         * Continues a search for token and session
         * objects that match a template, obtaining additional object
         * handles
         * @param session The session's handle
         * @param session The maximum number of object handles to be returned
         * @returns List of handles
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjects(session: Handle, maxObjectCount: number): Handle[];
        /**
         * Continues a search for token and session
         * objects that match a template, obtaining additional object
         * handles
         * @param session The session's handle
         * @returns Object's handle. If object is not found
         * the result is null
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjects(session: Handle): Handle | null;
        /**
         * Finishes a search for token and session objects
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjectsFinal(session: Handle): void;
        /**
         * Obtains the value of one or more object attributes
         * @param session The session's handle
         * @param object The object's handle
         * @param template Specifies attrs; gets values
         * @returns List of Attributes with values
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetAttributeValue(session: Handle, object: Handle, template: Template): Template;
        /**
         * Modifies the value of one or more object attributes
         * @param session The session's handle
         * @param object The object's handle
         * @param template Specifies attrs and values
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SetAttributeValue(session: Handle, object: Handle, template: Template): void;

        //#endregion

        //#region Encryption and decryption

        /**
         * Initializes an encryption operation
         * @param session The session's handle
         * @param mechanism The encryption mechanism
         * @param key Handle of encryption key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with encrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Encrypt(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Encrypt(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with encrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * Continues a multiple-part encryption operation
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Finishes a multiple-part encryption operation
         * @param session The session's handle
         * @param outData Last output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Initializes a decryption operation
         * @param session The session's handle
         * @param mechanism The decryption mechanism
         * @param key Handle of decryption key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Decrypt(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Decrypt(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * continues a multiple-part decryption operation
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted block
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Finishes a multiple-part decryption operation
         * @param session The session's handle
         * @param outData Last part of output data
         * @returns Sliced output data with decrypted final block
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptFinal(session: Handle, outData: Buffer): Buffer;

        /* Message digesting */

        /**
         * Initializes a message-digesting operation
         * @param session The session's handle
         * @param mechanism Digesting mechanism
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestInit(session: Handle, mechanism: Mechanism): void;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Digest(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Digest(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * continues a multiple-part message-digesting operation
         * operation, by digesting the value of a secret key as part of
         * the data already digested
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part message-digesting operation
         * @param session The session's handle
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Continues a multiple-part message-digesting operation by digesting the value of a secret key
         * @param session The session's handle
         * @param key The handle of the secret key to be digested
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestKey(session: Handle, key: Handle): void;

        //#endregion

        //#region Signing and MACing

        /**
         * initializes a signature (private key encryption)
         * operation, where the signature is (will be) an appendix to
         * the data, and plaintext cannot be recovered from the
         * signature
         * @param session The session's handle
         * @param mechanism Signature mechanism
         * @param key Handle of signature key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Sign(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Sign(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * Continues a multiple-part signature operation,
         * where the signature is (will be) an appendix to the data,
         * and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part signature operation,
         * returning the signature
         * @param session The session's handle
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Initializes a signature operation, where the data can be recovered from the signature
         * @param session The session's handle
         * @param mechanism The structure that specifies the signature mechanism 
         * @param key The handle of the signature key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignRecoverInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Signs data in a single operation, where the data can be recovered from the signature
         * @param session 
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignRecover(session: Handle, inData: Buffer, outData: Buffer): Buffer;

        //#endregion

        //#region Verifying signatures and MACs

        /**
         * initializes a verification operation, where the
         * signature is an appendix to the data, and plaintext cannot
         * cannot be recovered from the signature (e.g. DSA)
         * @param session The session's handle
         * @param mechanism Verification mechanism
         * @param key Verification key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @returns Verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Verify(session: Handle, inData: Buffer, signature: Buffer): boolean;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @param cb Async callback with verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Verify(session: Handle, inData: Buffer, signature: Buffer, cb: (error: Error, verify: boolean) => void): void;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @returns Verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyAsync(session: Handle, inData: Buffer, signature: Buffer): Promise<boolean>;
        /**
         * Continues a multiple-part verification
         * operation, where the signature is an appendix to the data,
         * and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part verification
         * operation, checking the signature
         * @param session The session's handle
         * @param signature Signature to verify
         * @returns
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyFinal(session: Handle, signature: Buffer): boolean;
        /**
         * Initializes a signature verification operation, where the data is recovered from the signature
         * @param session The session's handle
         * @param mechanism The structure that specifies the verification mechanism
         * @param key The handle of the verification key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        C_VerifyRecoverInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Verifies a signature in a single-part operation, where the data is recovered from the signature
         * @param session The session's handle
         * @param signature The signature to verify
         * @param outData The allocated buffer for recovered data
         * @return The sliced output data with recovered data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        C_VerifyRecover(session: Handle, signature: Buffer, outData: Buffer): Buffer;

        //#endregion

        //#region Key management

        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param template Template for new key
         * @returns The handle of the new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKey(session: Handle, mechanism: Mechanism, template: Template): Handle;
        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param template Template for new key
         * @param cb Async callback with handle of new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKey(session: Handle, mechanism: Mechanism, template: Template, cb: (error: Error, key: Handle) => void): void;
        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key generation mechanism
         * @param template The template for the new key
         * @returns The handle of the new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyAsync(session: Handle, mechanism: Mechanism, template: Template): Promise<Handle>;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @returns The pair of handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPair(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template): KeyPair;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @param cb Async callback with handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPair(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template, cb: (error: Error, keys: KeyPair) => void): void;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @returns Handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPairAsync(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template): Promise<KeyPair>;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @returns Sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKey(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer): Buffer;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @param cb Async callback with sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKey(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer, cb: (error: Error, wrappedKey: Buffer) => void): void;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @returns Sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKeyAsync(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer): Promise<Buffer>;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @returns The unwrapped key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKey(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template): Handle;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @param cb Async callback with new key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKey(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template, cb: (error: Error, key: Handle) => void): void;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @returns The unwrapped key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKeyAsync(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template): Promise<Handle>;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @returns The derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKey(session: Handle, mechanism: Mechanism, key: Handle, template: Template): Handle;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @param cb Async callback with the derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKey(session: Handle, mechanism: Mechanism, key: Handle, template: Template, cb: (error: Error, hKey: Handle) => void): void;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @returns The derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKeyAsync(session: Handle, mechanism: Mechanism, key: Handle, template: Template): Promise<Handle>;
        /**
         * Mixes additional seed material into the token's random number generator
         * @param session The session's handle
         * @param buf The seed material
         * @returns The seeded data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SeedRandom(session: Handle, buf: Buffer): Buffer;
        /**
         * Generates random data
         * @param session The session's handle
         * @param buf Init buffer
         * @returns The random data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateRandom(session: Handle, buf: Buffer): Buffer;
        //#endregion

        //#region Event management
        /**
         * Waits for a slot event, such as token insertion or token removal, to occur.
         * @param flags Determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits for a slot event to occur); use CKF_DONT_BLOCK for no blocking call
         * @param slotID The ID of the slot
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WaitForSlotEvent(flags: number, slotID: Handle): void;
        //#endregion

    }

    //#region Attributes
    export const CKA_CLASS: number;
    export const CKA_TOKEN: number;
    export const CKA_PRIVATE: number;
    export const CKA_LABEL: number;
    export const CKA_APPLICATION: number;
    export const CKA_VALUE: number;
    export const CKA_OBJECT_ID: number;
    export const CKA_CERTIFICATE_TYPE: number;
    export const CKA_ISSUER: number;
    export const CKA_SERIAL_NUMBER: number;
    export const CKA_AC_ISSUER: number;
    export const CKA_OWNER: number;
    export const CKA_ATTR_TYPES: number;
    export const CKA_TRUSTED: number;
    export const CKA_CERTIFICATE_CATEGORY: number;
    export const CKA_JAVA_MIDP_SECURITY_DOMAIN: number;
    export const CKA_URL: number;
    export const CKA_HASH_OF_SUBJECT_PUBLIC_KEY: number;
    export const CKA_HASH_OF_ISSUER_PUBLIC_KEY: number;
    export const CKA_NAME_HASH_ALGORITHM: number;
    export const CKA_CHECK_VALUE: number;
    export const CKA_KEY_TYPE: number;
    export const CKA_SUBJECT: number;
    export const CKA_ID: number;
    export const CKA_SENSITIVE: number;
    export const CKA_ENCRYPT: number;
    export const CKA_DECRYPT: number;
    export const CKA_WRAP: number;
    export const CKA_UNWRAP: number;
    export const CKA_SIGN: number;
    export const CKA_SIGN_RECOVER: number;
    export const CKA_VERIFY: number;
    export const CKA_VERIFY_RECOVER: number;
    export const CKA_DERIVE: number;
    export const CKA_START_DATE: number;
    export const CKA_END_DATE: number;
    export const CKA_MODULUS: number;
    export const CKA_MODULUS_BITS: number;
    export const CKA_PUBLIC_EXPONENT: number;
    export const CKA_PRIVATE_EXPONENT: number;
    export const CKA_PRIME_1: number;
    export const CKA_PRIME_2: number;
    export const CKA_EXPONENT_1: number;
    export const CKA_EXPONENT_2: number;
    export const CKA_COEFFICIENT: number;
    export const CKA_PRIME: number;
    export const CKA_SUBPRIME: number;
    export const CKA_BASE: number;
    export const CKA_PRIME_BITS: number;
    export const CKA_SUBPRIME_BITS: number;
    export const CKA_SUB_PRIME_BITS: number;
    export const CKA_VALUE_BITS: number;
    export const CKA_VALUE_LEN: number;
    export const CKA_EXTRACTABLE: number;
    export const CKA_LOCAL: number;
    export const CKA_NEVER_EXTRACTABLE: number;
    export const CKA_ALWAYS_SENSITIVE: number;
    export const CKA_KEY_GEN_MECHANISM: number;
    export const CKA_MODIFIABLE: number;
    export const CKA_COPYABLE: number;
    export const CKA_DESTROYABLE: number;
    export const CKA_ECDSA_PARAMS: number;
    export const CKA_EC_PARAMS: number;
    export const CKA_EC_POINT: number;
    export const CKA_SECONDARY_AUTH: number;
    export const CKA_AUTH_PIN_FLAGS: number;
    export const CKA_ALWAYS_AUTHENTICATE: number;
    export const CKA_WRAP_WITH_TRUSTED: number;
    export const CKA_WRAP_TEMPLATE: number;
    export const CKA_UNWRAP_TEMPLATE: number;
    export const CKA_DERIVE_TEMPLATE: number;
    export const CKA_OTP_FORMAT: number;
    export const CKA_OTP_LENGTH: number;
    export const CKA_OTP_TIME_INTERVAL: number;
    export const CKA_OTP_USER_FRIENDLY_MODE: number;
    export const CKA_OTP_CHALLENGE_REQUIREMENT: number;
    export const CKA_OTP_TIME_REQUIREMENT: number;
    export const CKA_OTP_COUNTER_REQUIREMENT: number;
    export const CKA_OTP_PIN_REQUIREMENT: number;
    export const CKA_OTP_COUNTER: number;
    export const CKA_OTP_TIME: number;
    export const CKA_OTP_USER_IDENTIFIER: number;
    export const CKA_OTP_SERVICE_IDENTIFIER: number;
    export const CKA_OTP_SERVICE_LOGO: number;
    export const CKA_OTP_SERVICE_LOGO_TYPE: number;
    export const CKA_GOSTR3410_PARAMS: number;
    export const CKA_GOSTR3411_PARAMS: number;
    export const CKA_GOST28147_PARAMS: number;
    export const CKA_HW_FEATURE_TYPE: number;
    export const CKA_RESET_ON_INIT: number;
    export const CKA_HAS_RESET: number;
    export const CKA_PIXEL_X: number;
    export const CKA_PIXEL_Y: number;
    export const CKA_RESOLUTION: number;
    export const CKA_CHAR_ROWS: number;
    export const CKA_CHAR_COLUMNS: number;
    export const CKA_COLOR: number;
    export const CKA_BITS_PER_PIXEL: number;
    export const CKA_CHAR_SETS: number;
    export const CKA_ENCODING_METHODS: number;
    export const CKA_MIME_TYPES: number;
    export const CKA_MECHANISM_TYPE: number;
    export const CKA_REQUIRED_CMS_ATTRIBUTES: number;
    export const CKA_DEFAULT_CMS_ATTRIBUTES: number;
    export const CKA_SUPPORTED_CMS_ATTRIBUTES: number;
    export const CKA_ALLOWED_MECHANISMS: number;
    export const CKA_VENDOR_DEFINED: number;
    //#endregion

    //#region Objects
    export const CKO_DATA: number;
    export const CKO_CERTIFICATE: number;
    export const CKO_PUBLIC_KEY: number;
    export const CKO_PRIVATE_KEY: number;
    export const CKO_SECRET_KEY: number;
    export const CKO_HW_FEATURE: number;
    export const CKO_DOMAIN_PARAMETERS: number;
    export const CKO_MECHANISM: number;
    export const CKO_OTP_KEY: number;
    export const CKO_VENDOR_DEFINED: number;
    //#endregion

    //#region Key types
    export const CKK_RSA: number;
    export const CKK_DSA: number;
    export const CKK_DH: number;
    export const CKK_ECDSA: number;
    export const CKK_EC: number;
    export const CKK_X9_42_DH: number;
    export const CKK_KEA: number;
    export const CKK_GENERIC_SECRET: number;
    export const CKK_RC2: number;
    export const CKK_RC4: number;
    export const CKK_DES: number;
    export const CKK_DES2: number;
    export const CKK_DES3: number;
    export const CKK_CAST: number;
    export const CKK_CAST3: number;
    export const CKK_CAST5: number;
    export const CKK_CAST128: number;
    export const CKK_RC5: number;
    export const CKK_IDEA: number;
    export const CKK_SKIPJACK: number;
    export const CKK_BATON: number;
    export const CKK_JUNIPER: number;
    export const CKK_CDMF: number;
    export const CKK_AES: number;
    export const CKK_BLOWFISH: number;
    export const CKK_TWOFISH: number;
    export const CKK_SECURID: number;
    export const CKK_HOTP: number;
    export const CKK_ACTI: number;
    export const CKK_CAMELLIA: number;
    export const CKK_ARIA: number;
    export const CKK_MD5_HMAC: number;
    export const CKK_SHA_1_HMAC: number;
    export const CKK_RIPEMD128_HMAC: number;
    export const CKK_RIPEMD160_HMAC: number;
    export const CKK_SHA256_HMAC: number;
    export const CKK_SHA384_HMAC: number;
    export const CKK_SHA512_HMAC: number;
    export const CKK_SHA224_HMAC: number;
    export const CKK_SEED: number;
    export const CKK_GOSTR3410: number;
    export const CKK_GOSTR3411: number;
    export const CKK_GOST28147: number;
    export const CKK_VENDOR_DEFINED: number;
    //#endregion

    //#region Mechanisms
    export const CKM_RSA_PKCS_KEY_PAIR_GEN: number;
    export const CKM_RSA_PKCS: number;
    export const CKM_RSA_9796: number;
    export const CKM_RSA_X_509: number;
    export const CKM_MD2_RSA_PKCS: number;
    export const CKM_MD5_RSA_PKCS: number;
    export const CKM_SHA1_RSA_PKCS: number;
    export const CKM_RIPEMD128_RSA_PKCS: number;
    export const CKM_RIPEMD160_RSA_PKCS: number;
    export const CKM_RSA_PKCS_OAEP: number;
    export const CKM_RSA_X9_31_KEY_PAIR_GEN: number;
    export const CKM_RSA_X9_31: number;
    export const CKM_SHA1_RSA_X9_31: number;
    export const CKM_RSA_PKCS_PSS: number;
    export const CKM_SHA1_RSA_PKCS_PSS: number;
    export const CKM_DSA_KEY_PAIR_GEN: number;
    export const CKM_DSA: number;
    export const CKM_DSA_SHA1: number;
    export const CKM_DSA_SHA224: number;
    export const CKM_DSA_SHA256: number;
    export const CKM_DSA_SHA384: number;
    export const CKM_DSA_SHA512: number;
    export const CKM_DH_PKCS_KEY_PAIR_GEN: number;
    export const CKM_DH_PKCS_DERIVE: number;
    export const CKM_X9_42_DH_KEY_PAIR_GEN: number;
    export const CKM_X9_42_DH_DERIVE: number;
    export const CKM_X9_42_DH_HYBRID_DERIVE: number;
    export const CKM_X9_42_MQV_DERIVE: number;
    export const CKM_SHA256_RSA_PKCS: number;
    export const CKM_SHA384_RSA_PKCS: number;
    export const CKM_SHA512_RSA_PKCS: number;
    export const CKM_SHA256_RSA_PKCS_PSS: number;
    export const CKM_SHA384_RSA_PKCS_PSS: number;
    export const CKM_SHA512_RSA_PKCS_PSS: number;
    export const CKM_SHA224_RSA_PKCS: number;
    export const CKM_SHA224_RSA_PKCS_PSS: number;
    export const CKM_RC2_KEY_GEN: number;
    export const CKM_RC2_ECB: number;
    export const CKM_RC2_CBC: number;
    export const CKM_RC2_MAC: number;
    export const CKM_RC2_MAC_GENERAL: number;
    export const CKM_RC2_CBC_PAD: number;
    export const CKM_RC4_KEY_GEN: number;
    export const CKM_RC4: number;
    export const CKM_DES_KEY_GEN: number;
    export const CKM_DES_ECB: number;
    export const CKM_DES_CBC: number;
    export const CKM_DES_MAC: number;
    export const CKM_DES_MAC_GENERAL: number;
    export const CKM_DES_CBC_PAD: number;
    export const CKM_DES2_KEY_GEN: number;
    export const CKM_DES3_KEY_GEN: number;
    export const CKM_DES3_ECB: number;
    export const CKM_DES3_CBC: number;
    export const CKM_DES3_MAC: number;
    export const CKM_DES3_MAC_GENERAL: number;
    export const CKM_DES3_CBC_PAD: number;
    export const CKM_DES3_CMAC_GENERAL: number;
    export const CKM_DES3_CMAC: number;
    export const CKM_CDMF_KEY_GEN: number;
    export const CKM_CDMF_ECB: number;
    export const CKM_CDMF_CBC: number;
    export const CKM_CDMF_MAC: number;
    export const CKM_CDMF_MAC_GENERAL: number;
    export const CKM_CDMF_CBC_PAD: number;
    export const CKM_DES_OFB64: number;
    export const CKM_DES_OFB8: number;
    export const CKM_DES_CFB64: number;
    export const CKM_DES_CFB8: number;
    export const CKM_MD2: number;
    export const CKM_MD2_HMAC: number;
    export const CKM_MD2_HMAC_GENERAL: number;
    export const CKM_MD5: number;
    export const CKM_MD5_HMAC: number;
    export const CKM_MD5_HMAC_GENERAL: number;
    export const CKM_SHA_1: number;
    export const CKM_SHA_1_HMAC: number;
    export const CKM_SHA_1_HMAC_GENERAL: number;
    export const CKM_RIPEMD128: number;
    export const CKM_RIPEMD128_HMAC: number;
    export const CKM_RIPEMD128_HMAC_GENERAL: number;
    export const CKM_RIPEMD160: number;
    export const CKM_RIPEMD160_HMAC: number;
    export const CKM_RIPEMD160_HMAC_GENERAL: number;
    export const CKM_SHA256: number;
    export const CKM_SHA256_HMAC: number;
    export const CKM_SHA256_HMAC_GENERAL: number;
    export const CKM_SHA224: number;
    export const CKM_SHA224_HMAC: number;
    export const CKM_SHA224_HMAC_GENERAL: number;
    export const CKM_SHA384: number;
    export const CKM_SHA384_HMAC: number;
    export const CKM_SHA384_HMAC_GENERAL: number;
    export const CKM_SHA512: number;
    export const CKM_SHA512_HMAC: number;
    export const CKM_SHA512_HMAC_GENERAL: number;
    export const CKM_SECURID_KEY_GEN: number;
    export const CKM_SECURID: number;
    export const CKM_HOTP_KEY_GEN: number;
    export const CKM_HOTP: number;
    export const CKM_ACTI: number;
    export const CKM_ACTI_KEY_GEN: number;
    export const CKM_CAST_KEY_GEN: number;
    export const CKM_CAST_ECB: number;
    export const CKM_CAST_CBC: number;
    export const CKM_CAST_MAC: number;
    export const CKM_CAST_MAC_GENERAL: number;
    export const CKM_CAST_CBC_PAD: number;
    export const CKM_CAST3_KEY_GEN: number;
    export const CKM_CAST3_ECB: number;
    export const CKM_CAST3_CBC: number;
    export const CKM_CAST3_MAC: number;
    export const CKM_CAST3_MAC_GENERAL: number;
    export const CKM_CAST3_CBC_PAD: number;
    export const CKM_CAST5_KEY_GEN: number;
    export const CKM_CAST128_KEY_GEN: number;
    export const CKM_CAST5_ECB: number;
    export const CKM_CAST128_ECB: number;
    export const CKM_CAST5_CBC: number;
    export const CKM_CAST128_CBC: number;
    export const CKM_CAST5_MAC: number;
    export const CKM_CAST128_MAC: number;
    export const CKM_CAST5_MAC_GENERAL: number;
    export const CKM_CAST128_MAC_GENERAL: number;
    export const CKM_CAST5_CBC_PAD: number;
    export const CKM_CAST128_CBC_PAD: number;
    export const CKM_RC5_KEY_GEN: number;
    export const CKM_RC5_ECB: number;
    export const CKM_RC5_CBC: number;
    export const CKM_RC5_MAC: number;
    export const CKM_RC5_MAC_GENERAL: number;
    export const CKM_RC5_CBC_PAD: number;
    export const CKM_IDEA_KEY_GEN: number;
    export const CKM_IDEA_ECB: number;
    export const CKM_IDEA_CBC: number;
    export const CKM_IDEA_MAC: number;
    export const CKM_IDEA_MAC_GENERAL: number;
    export const CKM_IDEA_CBC_PAD: number;
    export const CKM_GENERIC_SECRET_KEY_GEN: number;
    export const CKM_CONCATENATE_BASE_AND_KEY: number;
    export const CKM_CONCATENATE_BASE_AND_DATA: number;
    export const CKM_CONCATENATE_DATA_AND_BASE: number;
    export const CKM_XOR_BASE_AND_DATA: number;
    export const CKM_EXTRACT_KEY_FROM_KEY: number;
    export const CKM_SSL3_PRE_MASTER_KEY_GEN: number;
    export const CKM_SSL3_MASTER_KEY_DERIVE: number;
    export const CKM_SSL3_KEY_AND_MAC_DERIVE: number;
    export const CKM_SSL3_MASTER_KEY_DERIVE_DH: number;
    export const CKM_TLS_PRE_MASTER_KEY_GEN: number;
    export const CKM_TLS_MASTER_KEY_DERIVE: number;
    export const CKM_TLS_KEY_AND_MAC_DERIVE: number;
    export const CKM_TLS_MASTER_KEY_DERIVE_DH: number;
    export const CKM_TLS_PRF: number;
    export const CKM_SSL3_MD5_MAC: number;
    export const CKM_SSL3_SHA1_MAC: number;
    export const CKM_MD5_KEY_DERIVATION: number;
    export const CKM_MD2_KEY_DERIVATION: number;
    export const CKM_SHA1_KEY_DERIVATION: number;
    export const CKM_SHA256_KEY_DERIVATION: number;
    export const CKM_SHA384_KEY_DERIVATION: number;
    export const CKM_SHA512_KEY_DERIVATION: number;
    export const CKM_SHA224_KEY_DERIVATION: number;
    export const CKM_PBE_MD2_DES_CBC: number;
    export const CKM_PBE_MD5_DES_CBC: number;
    export const CKM_PBE_MD5_CAST_CBC: number;
    export const CKM_PBE_MD5_CAST3_CBC: number;
    export const CKM_PBE_MD5_CAST5_CBC: number;
    export const CKM_PBE_MD5_CAST128_CBC: number;
    export const CKM_PBE_SHA1_CAST5_CBC: number;
    export const CKM_PBE_SHA1_CAST128_CBC: number;
    export const CKM_PBE_SHA1_RC4_128: number;
    export const CKM_PBE_SHA1_RC4_40: number;
    export const CKM_PBE_SHA1_DES3_EDE_CBC: number;
    export const CKM_PBE_SHA1_DES2_EDE_CBC: number;
    export const CKM_PBE_SHA1_RC2_128_CBC: number;
    export const CKM_PBE_SHA1_RC2_40_CBC: number;
    export const CKM_PKCS5_PBKD2: number;
    export const CKM_PBA_SHA1_WITH_SHA1_HMAC: number;
    export const CKM_WTLS_PRE_MASTER_KEY_GEN: number;
    export const CKM_WTLS_MASTER_KEY_DERIVE: number;
    export const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: number;
    export const CKM_WTLS_PRF: number;
    export const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: number;
    export const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: number;
    export const CKM_KEY_WRAP_LYNKS: number;
    export const CKM_KEY_WRAP_SET_OAEP: number;
    export const CKM_CAMELLIA_KEY_GEN: number;
    export const CKM_CAMELLIA_ECB: number;
    export const CKM_CAMELLIA_CBC: number;
    export const CKM_CAMELLIA_MAC: number;
    export const CKM_CAMELLIA_MAC_GENERAL: number;
    export const CKM_CAMELLIA_CBC_PAD: number;
    export const CKM_CAMELLIA_ECB_ENCRYPT_DATA: number;
    export const CKM_CAMELLIA_CBC_ENCRYPT_DATA: number;
    export const CKM_CAMELLIA_CTR: number;
    export const CKM_ARIA_KEY_GEN: number;
    export const CKM_ARIA_ECB: number;
    export const CKM_ARIA_CBC: number;
    export const CKM_ARIA_MAC: number;
    export const CKM_ARIA_MAC_GENERAL: number;
    export const CKM_ARIA_CBC_PAD: number;
    export const CKM_ARIA_ECB_ENCRYPT_DATA: number;
    export const CKM_ARIA_CBC_ENCRYPT_DATA: number;
    export const CKM_SEED_KEY_GEN: number;
    export const CKM_SEED_ECB: number;
    export const CKM_SEED_CBC: number;
    export const CKM_SEED_MAC: number;
    export const CKM_SEED_MAC_GENERAL: number;
    export const CKM_SEED_CBC_PAD: number;
    export const CKM_SEED_ECB_ENCRYPT_DATA: number;
    export const CKM_SEED_CBC_ENCRYPT_DATA: number;
    export const CKM_SKIPJACK_KEY_GEN: number;
    export const CKM_SKIPJACK_ECB64: number;
    export const CKM_SKIPJACK_CBC64: number;
    export const CKM_SKIPJACK_OFB64: number;
    export const CKM_SKIPJACK_CFB64: number;
    export const CKM_SKIPJACK_CFB32: number;
    export const CKM_SKIPJACK_CFB16: number;
    export const CKM_SKIPJACK_CFB8: number;
    export const CKM_SKIPJACK_WRAP: number;
    export const CKM_SKIPJACK_PRIVATE_WRAP: number;
    export const CKM_SKIPJACK_RELAYX: number;
    export const CKM_KEA_KEY_PAIR_GEN: number;
    export const CKM_KEA_KEY_DERIVE: number;
    export const CKM_FORTEZZA_TIMESTAMP: number;
    export const CKM_BATON_KEY_GEN: number;
    export const CKM_BATON_ECB128: number;
    export const CKM_BATON_ECB96: number;
    export const CKM_BATON_CBC128: number;
    export const CKM_BATON_COUNTER: number;
    export const CKM_BATON_SHUFFLE: number;
    export const CKM_BATON_WRAP: number;
    export const CKM_ECDSA_KEY_PAIR_GEN: number;
    export const CKM_EC_KEY_PAIR_GEN: number;
    export const CKM_ECDSA: number;
    export const CKM_ECDSA_SHA1: number;
    export const CKM_ECDSA_SHA224: number;
    export const CKM_ECDSA_SHA256: number;
    export const CKM_ECDSA_SHA384: number;
    export const CKM_ECDSA_SHA512: number;
    export const CKM_ECDH1_DERIVE: number;
    export const CKM_ECDH1_COFACTOR_DERIVE: number;
    export const CKM_ECMQV_DERIVE: number;
    export const CKM_JUNIPER_KEY_GEN: number;
    export const CKM_JUNIPER_ECB128: number;
    export const CKM_JUNIPER_CBC128: number;
    export const CKM_JUNIPER_COUNTER: number;
    export const CKM_JUNIPER_SHUFFLE: number;
    export const CKM_JUNIPER_WRAP: number;
    export const CKM_FASTHASH: number;
    export const CKM_AES_KEY_GEN: number;
    export const CKM_AES_ECB: number;
    export const CKM_AES_CBC: number;
    export const CKM_AES_MAC: number;
    export const CKM_AES_MAC_GENERAL: number;
    export const CKM_AES_CBC_PAD: number;
    export const CKM_AES_CTR: number;
    export const CKM_AES_CTS: number;
    export const CKM_AES_CMAC: number;
    export const CKM_AES_CMAC_GENERAL: number;
    export const CKM_BLOWFISH_KEY_GEN: number;
    export const CKM_BLOWFISH_CBC: number;
    export const CKM_TWOFISH_KEY_GEN: number;
    export const CKM_TWOFISH_CBC: number;
    export const CKM_AES_GCM: number;
    export const CKM_AES_CCM: number;
    export const CKM_AES_KEY_WRAP: number;
    export const CKM_AES_KEY_WRAP_PAD: number;
    export const CKM_BLOWFISH_CBC_PAD: number;
    export const CKM_TWOFISH_CBC_PAD: number;
    export const CKM_DES_ECB_ENCRYPT_DATA: number;
    export const CKM_DES_CBC_ENCRYPT_DATA: number;
    export const CKM_DES3_ECB_ENCRYPT_DATA: number;
    export const CKM_DES3_CBC_ENCRYPT_DATA: number;
    export const CKM_AES_ECB_ENCRYPT_DATA: number;
    export const CKM_AES_CBC_ENCRYPT_DATA: number;
    export const CKM_GOSTR3410_KEY_PAIR_GEN: number;
    export const CKM_GOSTR3410: number;
    export const CKM_GOSTR3410_WITH_GOSTR3411: number;
    export const CKM_GOSTR3410_KEY_WRAP: number;
    export const CKM_GOSTR3410_DERIVE: number;
    export const CKM_GOSTR3411: number;
    export const CKM_GOSTR3411_HMAC: number;
    export const CKM_GOST28147_KEY_GEN: number;
    export const CKM_GOST28147_ECB: number;
    export const CKM_GOST28147: number;
    export const CKM_GOST28147_MAC: number;
    export const CKM_GOST28147_KEY_WRAP: number;
    export const CKM_DSA_PARAMETER_GEN: number;
    export const CKM_DH_PKCS_PARAMETER_GEN: number;
    export const CKM_X9_42_DH_PARAMETER_GEN: number;
    export const CKM_AES_OFB: number;
    export const CKM_AES_CFB64: number;
    export const CKM_AES_CFB8: number;
    export const CKM_AES_CFB128: number;
    export const CKM_RSA_PKCS_TPM_1_1: number;
    export const CKM_RSA_PKCS_OAEP_TPM_1_1: number;
    export const CKM_VENDOR_DEFINED: number;
    //#endregion

    //#region Session flags
    export const CKF_RW_SESSION: number;
    export const CKF_SERIAL_SESSION: number;
    //#endregion

    //#region Follows
    export const CKF_HW: number;
    export const CKF_ENCRYPT: number;
    export const CKF_DECRYPT: number;
    export const CKF_DIGEST: number;
    export const CKF_SIGN: number;
    export const CKF_SIGN_RECOVER: number;
    export const CKF_VERIFY: number;
    export const CKF_VERIFY_RECOVER: number;
    export const CKF_GENERATE: number;
    export const CKF_GENERATE_KEY_PAIR: number;
    export const CKF_WRAP: number;
    export const CKF_UNWRAP: number;
    export const CKF_DERIVE: number;
    //#endregion

    //#region Token Information Flags
    export const CKF_RNG: number;
    export const CKF_WRITE_PROTECTED: number;
    export const CKF_LOGIN_REQUIRED: number;
    export const CKF_USER_PIN_INITIALIZED: number;
    export const CKF_RESTORE_KEY_NOT_NEEDED: number;
    export const CKF_CLOCK_ON_TOKEN: number;
    export const CKF_PROTECTED_AUTHENTICATION_PATH: number;
    export const CKF_DUAL_CRYPTO_OPERATIONS: number;
    export const CKF_TOKEN_INITIALIZED: number;
    export const CKF_SECONDARY_AUTHENTICATION: number;
    export const CKF_USER_PIN_COUNT_LOW: number;
    export const CKF_USER_PIN_FINAL_TRY: number;
    export const CKF_USER_PIN_LOCKED: number;
    export const CKF_USER_PIN_TO_BE_CHANGED: number;
    export const CKF_SO_PIN_COUNT_LOW: number;
    export const CKF_SO_PIN_FINAL_TRY: number;
    export const CKF_SO_PIN_LOCKED: number;
    export const CKF_SO_PIN_TO_BE_CHANGED: number;
    export const CKF_ERROR_STATE: number;
    //#endregion

    //#region Event Flags
    export const CKF_DONT_BLOCK: number;
    //#endregion

    //#region Certificates
    export const CKC_X_509: number;
    export const CKC_X_509_ATTR_CERT: number;
    export const CKC_WTLS: number;
    //#endregion

    //#region MGFs
    export const CKG_MGF1_SHA1: number;
    export const CKG_MGF1_SHA256: number;
    export const CKG_MGF1_SHA384: number;
    export const CKG_MGF1_SHA512: number;
    export const CKG_MGF1_SHA224: number;
    //#endregion

    //#region KDFs
    export const CKD_NULL: number;
    export const CKD_SHA1_KDF: number;
    export const CKD_SHA1_KDF_ASN1: number;
    export const CKD_SHA1_KDF_CONCATENATE: number;
    export const CKD_SHA224_KDF: number;
    export const CKD_SHA256_KDF: number;
    export const CKD_SHA384_KDF: number;
    export const CKD_SHA512_KDF: number;
    export const CKD_CPDIVERSIFY_KDF: number;
    //#endregion

    //#region Mech params
    export const CK_PARAMS_AES_CBC: number;
    export const CK_PARAMS_AES_CCM: number;
    export const CK_PARAMS_AES_GCM: number;
    export const CK_PARAMS_RSA_OAEP: number;
    export const CK_PARAMS_RSA_PSS: number;
    export const CK_PARAMS_EC_DH: number;
    export const CK_PARAMS_AES_GCM_v240: number;
    //#endregion

    //#region User types
    export const CKU_SO: number;
    export const CKU_USER: number;
    export const CKU_CONTEXT_SPECIFIC: number;
    //#endregion

    // Initialize flags
    export const CKF_LIBRARY_CANT_CREATE_OS_THREADS: number;
    export const CKF_OS_LOCKING_OK: number;

    //#region Result values
    export const CKR_OK: number;
    export const CKR_CANCEL: number;
    export const CKR_HOST_MEMORY: number;
    export const CKR_SLOT_ID_INVALID: number;
    export const CKR_GENERAL_ERROR: number;
    export const CKR_FUNCTION_FAILED: number;
    export const CKR_ARGUMENTS_BAD: number;
    export const CKR_NO_EVENT: number;
    export const CKR_NEED_TO_CREATE_THREADS: number;
    export const CKR_CANT_LOCK: number;
    export const CKR_ATTRIBUTE_READ_ONLY: number;
    export const CKR_ATTRIBUTE_SENSITIVE: number;
    export const CKR_ATTRIBUTE_TYPE_INVALID: number;
    export const CKR_ATTRIBUTE_VALUE_INVALID: number;
    export const CKR_DATA_INVALID: number;
    export const CKR_DATA_LEN_RANGE: number;
    export const CKR_DEVICE_ERROR: number;
    export const CKR_DEVICE_MEMORY: number;
    export const CKR_DEVICE_REMOVED: number;
    export const CKR_ENCRYPTED_DATA_INVALID: number;
    export const CKR_ENCRYPTED_DATA_LEN_RANGE: number;
    export const CKR_FUNCTION_CANCELED: number;
    export const CKR_FUNCTION_NOT_PARALLEL: number;
    export const CKR_FUNCTION_NOT_SUPPORTED: number;
    export const CKR_KEY_HANDLE_INVALID: number;
    export const CKR_KEY_SIZE_RANGE: number;
    export const CKR_KEY_TYPE_INCONSISTENT: number;
    export const CKR_KEY_NOT_NEEDED: number;
    export const CKR_KEY_CHANGED: number;
    export const CKR_KEY_NEEDED: number;
    export const CKR_KEY_INDIGESTIBLE: number;
    export const CKR_KEY_FUNCTION_NOT_PERMITTED: number;
    export const CKR_KEY_NOT_WRAPPABLE: number;
    export const CKR_KEY_UNEXTRACTABLE: number;
    export const CKR_MECHANISM_INVALID: number;
    export const CKR_MECHANISM_PARAM_INVALID: number;
    export const CKR_OBJECT_HANDLE_INVALID: number;
    export const CKR_OPERATION_ACTIVE: number;
    export const CKR_OPERATION_NOT_INITIALIZED: number;
    export const CKR_PIN_INCORRECT: number;
    export const CKR_PIN_INVALID: number;
    export const CKR_PIN_LEN_RANGE: number;
    export const CKR_PIN_EXPIRED: number;
    export const CKR_PIN_LOCKED: number;
    export const CKR_SESSION_CLOSED: number;
    export const CKR_SESSION_COUNT: number;
    export const CKR_SESSION_HANDLE_INVALID: number;
    export const CKR_SESSION_PARALLEL_NOT_SUPPORTED: number;
    export const CKR_SESSION_READ_ONLY: number;
    export const CKR_SESSION_EXISTS: number;
    export const CKR_SESSION_READ_ONLY_EXISTS: number;
    export const CKR_SESSION_READ_WRITE_SO_EXISTS: number;
    export const CKR_SIGNATURE_INVALID: number;
    export const CKR_SIGNATURE_LEN_RANGE: number;
    export const CKR_TEMPLATE_INCOMPLETE: number;
    export const CKR_TEMPLATE_INCONSISTENT: number;
    export const CKR_TOKEN_NOT_PRESENT: number;
    export const CKR_TOKEN_NOT_RECOGNIZED: number;
    export const CKR_TOKEN_WRITE_PROTECTED: number;
    export const CKR_UNWRAPPING_KEY_HANDLE_INVALID: number;
    export const CKR_UNWRAPPING_KEY_SIZE_RANGE: number;
    export const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: number;
    export const CKR_USER_ALREADY_LOGGED_IN: number;
    export const CKR_USER_NOT_LOGGED_IN: number;
    export const CKR_USER_PIN_NOT_INITIALIZED: number;
    export const CKR_USER_TYPE_INVALID: number;
    export const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: number;
    export const CKR_USER_TOO_MANY_TYPES: number;
    export const CKR_WRAPPED_KEY_INVALID: number;
    export const CKR_WRAPPED_KEY_LEN_RANGE: number;
    export const CKR_WRAPPING_KEY_HANDLE_INVALID: number;
    export const CKR_WRAPPING_KEY_SIZE_RANGE: number;
    export const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: number;
    export const CKR_RANDOM_SEED_NOT_SUPPORTED: number;
    export const CKR_RANDOM_NO_RNG: number;
    export const CKR_DOMAIN_PARAMS_INVALID: number;
    export const CKR_BUFFER_TOO_SMALL: number;
    export const CKR_SAVED_STATE_INVALID: number;
    export const CKR_INFORMATION_SENSITIVE: number;
    export const CKR_STATE_UNSAVEABLE: number;
    export const CKR_CRYPTOKI_NOT_INITIALIZED: number;
    export const CKR_CRYPTOKI_ALREADY_INITIALIZED: number;
    export const CKR_MUTEX_BAD: number;
    export const CKR_MUTEX_NOT_LOCKED: number;
    export const CKR_NEW_PIN_MODE: number;
    export const CKR_NEXT_OTP: number;
    export const CKR_EXCEEDED_MAX_ITERATIONS: number;
    export const CKR_FIPS_SELF_TEST_FAILED: number;
    export const CKR_LIBRARY_LOAD_FAILED: number;
    export const CKR_PIN_TOO_WEAK: number;
    export const CKR_PUBLIC_KEY_INVALID: number;
    export const CKR_FUNCTION_REJECTED: number;
    //#endregion

    /**
     * Exception from native module
     */
    export class NativeError extends Error {
        /**
         * Native library call stack. Default is empty string
         */
        public readonly nativeStack: string;
        /**
         * Native function name. Default is empty string
         */
        public readonly method: string;
        /**
         * Initialize new instance of NativeError
         * @param message Error message
         */
        public constructor(message?: string, method?: string);
    }

    /**
     * Exception with the name and value of PKCS#11 return value
     */
    export class Pkcs11Error extends NativeError {
        /**
         * PKCS#11 result value. Default is 0
         */
        public readonly code: number;
        /**
         * Initialize new instance of Pkcs11Error
         * @param message Error message
         * @param code PKCS#11 result value
         * @param method The name of PKCS#11 method
         */
        public constructor(message?: string, code?: number, method?: string);
    }
}

export default pkcs11js;