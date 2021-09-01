{-# LANGUAGE QuasiQuotes #-}
import           Criterion.Main

import           Auth.Biscuit
import           Data.Maybe     (fromJust)

buildToken :: Keypair -> IO Biscuit
buildToken keypair = do
  mkBiscuit keypair [block|user_id(#authority, "user_1234");|]

-- Our benchmark harness.
main = do
  keypair <- newKeypair
  biscuit <- buildToken keypair
  let pubkey = publicKey keypair
  let biscuitBs = serialize biscuit
  defaultMain [
    bgroup "biscuit" [ bench "mkBiscuit"  $ whnfIO (buildToken keypair)
                     , bench "parse"      $ whnf parse biscuitBs
                     , bench "serialize"  $ whnf serialize biscuit
                     , bench "checkSig"   $ whnfIO (checkBiscuitSignature biscuit pubkey)
                     , bench "verify"     $ whnfIO (verifyBiscuit biscuit [verifier|allow if user_id(#authority, "user_1234");|] pubkey)
                     ]
    ]
