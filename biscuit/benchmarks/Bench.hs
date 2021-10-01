{-# LANGUAGE QuasiQuotes #-}
import           Criterion.Main

import           Auth.Biscuit
import           Data.Maybe     (fromJust)

buildToken :: SecretKey -> IO (Biscuit Open Checked)
buildToken sk = do
  mkBiscuit sk [block|user_id("user_1234");|]

-- Our benchmark harness.
main = do
  sk <- newSecret
  biscuit <- buildToken sk
  let pk = toPublic sk
  let biscuitBs = serialize biscuit
  defaultMain [
    bgroup "biscuit" [ bench "mkBiscuit"  $ whnfIO (buildToken sk)
                     , bench "parse"      $ whnf (parse pk) biscuitBs
                     , bench "serialize"  $ whnf serialize biscuit
                     , bench "verify"     $ whnfIO (verifyBiscuit biscuit [authorizer|allow if user_id("user_1234");|])
                     ]
    ]
