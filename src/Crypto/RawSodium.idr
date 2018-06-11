module Crypto.RawSodium


%lib     C "sodium"
%link    C "sodium_glue.o"
%include C "sodium_glue.h"


-- RAW INTERFACE

-- Key and nonce lengths

export
box_nonceLength : IO Int
box_nonceLength = foreign FFI_C "box_nonceLength" (IO Int)

export
box_secretKeyLength : IO Int
box_secretKeyLength = foreign FFI_C "box_secretKeyLength" (IO Int)

export
box_publicKeyLength : IO Int
box_publicKeyLength =  foreign FFI_C "box_publicKeyLength" (IO Int)

export
secretbox_nonceLength : IO Int
secretbox_nonceLength = foreign FFI_C "secretbox_nonceLength" (IO Int)

export
secretbox_keyLength : IO Int
secretbox_keyLength = foreign FFI_C "secretbox_keyLength" (IO Int)


-- Create/read/write keys

export
do_newKey : Int -> IO ManagedPtr
do_newKey len = do p <- foreign FFI_C "mkKey" (Int -> IO Ptr) len
                   pure $ prim__registerPtr p (len+16)

export
do_getKeyLen : ManagedPtr -> IO Int
do_getKeyLen p = foreign FFI_C "keyLen" (ManagedPtr -> IO Int) p

export
do_getKeyIdx : ManagedPtr -> Int -> IO Int
do_getKeyIdx p i = foreign FFI_C "keyIdx" (ManagedPtr -> Int -> IO Int) p i

export
do_setKeyIdx : ManagedPtr -> Int -> Int -> IO ()
do_setKeyIdx p i b
     = foreign FFI_C "setKeyIdx" (ManagedPtr -> Int -> Int -> IO ()) p i b


-- Create/read/write nonces

export
do_newNonce : Int -> IO ManagedPtr
do_newNonce len = do p <- foreign FFI_C "mkNonce" (Int -> IO Ptr) len
                     pure $ prim__registerPtr p (len+16)

export
do_newNonceFromString : String -> IO ManagedPtr
do_newNonceFromString s
     = do p <- foreign FFI_C "mkNonceFromString" (String -> IO Ptr) s
          pure $ prim__registerPtr p (cast (length s) + 16)

export
do_setNonceIdx : ManagedPtr -> Int -> Int -> IO ()
do_setNonceIdx p i b
     = foreign FFI_C "setNonceIdx" (ManagedPtr -> Int -> Int -> IO ()) p i b


-- Making/reading boxes

export
do_newBox : Int -> IO ManagedPtr
do_newBox len = do p <- foreign FFI_C "newBox" (Int -> IO Ptr) len
                   pure $ prim__registerPtr p (len + 16)

export
do_newSecretBox : Int -> IO ManagedPtr
do_newSecretBox len = do p <- foreign FFI_C "newBox" (Int -> IO Ptr) len
                         pure $ prim__registerPtr p (len + 16)

export
do_getBoxLen : ManagedPtr -> IO Int
do_getBoxLen p = foreign FFI_C "getEncLen" (ManagedPtr -> IO Int) p

export
do_getBoxIdx : ManagedPtr -> Int -> IO Int
do_getBoxIdx p i = foreign FFI_C "getEncByte" (ManagedPtr -> Int -> IO Int) p i

do_setBoxIdx : ManagedPtr -> Int -> Int -> IO ()
do_setBoxIdx p i b
     = foreign FFI_C "setEncByte" (ManagedPtr -> Int -> Int -> IO ()) p i b


-- Reading results of operations (symmetric or public key)

export
do_readBoxOpen : ManagedPtr -> IO String
do_readBoxOpen p = foreign FFI_C "getDec" (ManagedPtr -> IO String) p


-- Symmetric keys

export
do_cryptoSecretBox : (msg : String) ->
                     (nonce : ManagedPtr) ->
                     (key : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoSecretBox m n k
   = do p <- foreign FFI_C "do_crypto_secretbox"
                     (String -> ManagedPtr -> ManagedPtr -> IO Ptr) m n k
        if !(nullPtr p)
           then pure Nothing
           else do boxlen <- foreign FFI_C "getEncSize" (Ptr -> IO Int) p
                   pure $ Just (prim__registerPtr p (boxlen + 16))


export
do_cryptoSecretBoxOpen : (ciphertext : ManagedPtr) ->
                         (nonce : ManagedPtr) ->
                         (key : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoSecretBoxOpen c n k
   = do p <- foreign FFI_C "do_crypto_secretbox_open"
                     (ManagedPtr -> ManagedPtr -> ManagedPtr -> IO Ptr) c n k
        if !(nullPtr p)
           then pure Nothing
           else do boxlen <- foreign FFI_C "getDecSize" (Ptr -> IO Int) p
                   pure $ Just (prim__registerPtr p (boxlen + 16))


-- Public keys

export
do_newKeyPair : IO Ptr
do_newKeyPair = foreign FFI_C "newKeyPair" (IO Ptr)

export
do_getPublic : Ptr -> IO ManagedPtr
do_getPublic kp = do p <- foreign FFI_C "getPublic" (Ptr -> IO Ptr) kp
                     len <- foreign FFI_C "keyLen" (Ptr -> IO Int) p
                     pure $ prim__registerPtr p (len + 16)

export
do_getSecret : Ptr -> IO ManagedPtr
do_getSecret kp = do p <- foreign FFI_C "getSecret" (Ptr -> IO Ptr) kp
                     len <- foreign FFI_C "keyLen" (Ptr -> IO Int) p
                     pure $ prim__registerPtr p (len + 16)

export
do_cryptoBox : (msg : String) ->
               (nonce : ManagedPtr) ->
               (pkey : ManagedPtr) ->
               (skey : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoBox m n pk sk
   = do p <- foreign FFI_C "do_crypto_box"
                     (String -> ManagedPtr -> ManagedPtr -> ManagedPtr -> IO Ptr) m n pk sk
        if !(nullPtr p)
           then pure Nothing
           else do boxlen <- foreign FFI_C "getEncSize" (Ptr -> IO Int) p
                   pure $ Just (prim__registerPtr p (boxlen + 16))

export
do_cryptoBoxOpen : (ciphertext : ManagedPtr) ->
                   (nonce : ManagedPtr) ->
                   (pkey : ManagedPtr) ->
                   (skey : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoBoxOpen c n pk sk
   = do p <- foreign FFI_C "do_crypto_box_open"
                     (ManagedPtr -> ManagedPtr -> ManagedPtr -> ManagedPtr -> IO Ptr) c n pk sk
        if !(nullPtr p)
           then pure Nothing
           else do boxlen <- foreign FFI_C "getDecSize" (Ptr -> IO Int) p
                   pure $ Just (prim__registerPtr p (boxlen + 16))


-- Releasing memory for keys and results of encryption/decryption

-- do_freeBox : Ptr -> IO ()
-- do_freeBox p = foreign FFI_C "freeEnc" (Ptr -> IO ()) p
--
-- do_freeBoxOpen : Ptr -> IO ()
-- do_freeBoxOpen p = foreign FFI_C "freeDec" (Ptr -> IO ()) p
--
-- do_freeKey : Ptr -> IO ()
-- do_freeKey p = foreign FFI_C "freeKey" (Ptr -> IO ()) p

export
do_freeKeyPair : Ptr -> IO ()
do_freeKeyPair p = foreign FFI_C "freeKeyPair" (Ptr -> IO ()) p
