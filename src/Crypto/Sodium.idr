module Crypto.Sodium


import Crypto.RawSodium


-- Key generation

export
data Key = MkKey ManagedPtr

newKey : (len : Int) -> IO Key
newKey l = pure $ MkKey !(do_newKey l)

export
newSymmKey : IO Key
newSymmKey = do len <- secretbox_keyLength
                newKey len

export
newSecretKey : IO Key
newSecretKey = do len <- box_secretKeyLength
                  newKey len

export
newPublicKey : IO Key
newPublicKey = do len <- box_publicKeyLength
                  newKey len

export
newKeyPair : IO (Key, Key)
newKeyPair = do kp <- do_newKeyPair
                pk <- do_getPublic kp
                sk <- do_getSecret kp
                do_freeKeyPair kp
                pure (MkKey pk, MkKey sk)

export
keyLen : Key -> Int
keyLen (MkKey k) = unsafePerformIO (do_getKeyLen k)

export
keyIdx : Key -> Int -> Int
keyIdx (MkKey k) i = unsafePerformIO (do_getKeyIdx k i)

export
setKeyIdx : Key -> Int -> Int -> IO ()
setKeyIdx (MkKey k) i b = do_setKeyIdx k i b


-- Nonces

export
data Nonce = MkNonce ManagedPtr

export
newNonce : (len : Int) -> IO Nonce
newNonce l = pure $ MkNonce !(do_newNonce l)

export
newNonceFromString : (str : String) -> IO Nonce
newNonceFromString str = pure $ MkNonce !(do_newNonceFromString str)

export
setNonceIdx : Nonce -> Int -> Int -> IO ()
setNonceIdx (MkNonce k) i b = do_setNonceIdx k i b


-- An Encrypted box holds raw encrypted data, and its length
export
data EncryptedBox = MkEnc ManagedPtr | EncFailed

export
newSymmBox : Int -> IO EncryptedBox
newSymmBox l = pure $ MkEnc !(do_newSecretBox l)

export
newBox : Int -> IO EncryptedBox
newBox l = pure $ MkEnc !(do_newBox l)

export
getBoxLen : EncryptedBox -> Int
getBoxLen (MkEnc e) = unsafePerformIO $ do_getBoxLen e

export
getBoxIdx : EncryptedBox -> Int -> Int
getBoxIdx (MkEnc e) i = unsafePerformIO $ do_getBoxIdx e i

export
getBytes : EncryptedBox -> List Int
getBytes e = getAll [] 0 (getBoxLen e)
   where getAll : List Int -> Int -> Int -> List Int
         getAll acc i len
             = if i == len
                  then reverse acc
                  else getAll (getBoxIdx e i :: acc) (i + 1) len

export
validBox : EncryptedBox -> Bool
validBox (MkEnc e) = True
validBox EncFailed = False

-- freeBox : EncryptedBox -> IO ()
-- freeBox (MkEnc e) = do_freeBox e


-- An open box holds plain text, and its length

export
data OpenBox = MkDec ManagedPtr | DecFailed

export
readBox : OpenBox -> String
readBox (MkDec p) = unsafePerformIO (do_readBoxOpen p)

export
validOpenBox : OpenBox -> Bool
validOpenBox (MkDec e) = True
validOpenBox DecFailed = False

-- freeOpenBox : OpenBox -> IO ()
-- freeOpenBox (MkDec e) = do_freeBoxOpen e


-- Nonce lengths

export
symmNonceLength : Int
symmNonceLength = unsafePerformIO secretbox_nonceLength

export
nonceLength : Int
nonceLength = unsafePerformIO box_nonceLength


-- Symmetric key encryption

export
cryptoSecretBox : (plaintext : String) -> (nonce : Nonce) ->
                  (key : Key) -> IO EncryptedBox
cryptoSecretBox m (MkNonce n) (MkKey k)
    = case !(do_cryptoSecretBox m n k) of
           Just p => pure (MkEnc p)
           Nothing => pure EncFailed

export
cryptoSecretBoxOpen : (ciphertext : EncryptedBox) -> (nonce : Nonce) ->
                      (key : Key) -> IO OpenBox
cryptoSecretBoxOpen (MkEnc e) (MkNonce n) (MkKey k)
    = case !(do_cryptoSecretBoxOpen e n k) of
           Just p => pure (MkDec p)
           Nothing => pure DecFailed


-- Public key encryption

export
cryptoBox : (plaintext : String) -> (nonce : Nonce) ->
            (pkey : Key) -> (skey : Key) -> IO EncryptedBox
cryptoBox m (MkNonce n) (MkKey pk) (MkKey sk)
    = case !(do_cryptoBox m n pk sk) of
           Just p => pure (MkEnc p)
           Nothing => pure EncFailed

export
cryptoBoxOpen : (ciphertext : EncryptedBox) -> (nonce : Nonce) ->
                (pkey : Key) -> (skey : Key) -> IO OpenBox
cryptoBoxOpen (MkEnc e) (MkNonce n) (MkKey pk) (MkKey sk)
    = case !(do_cryptoBoxOpen e n pk sk) of
           Just p => pure (MkDec p)
           Nothing => pure DecFailed
