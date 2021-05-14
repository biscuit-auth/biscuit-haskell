module Spec where

import           Test.Tasty

import qualified Spec.Crypto       as Crypto
import qualified Spec.Executor     as Executor
import qualified Spec.Parser       as Parser
import qualified Spec.Quasiquoter  as Quasiquoter
import qualified Spec.Roundtrip    as Roundtrip
import qualified Spec.Samples      as Samples
import qualified Spec.Verification as Verification

main :: IO ()
main = defaultMain $ testGroup "biscuit-haskell"
  [ Crypto.specs
  , Executor.specs
  , Parser.specs
  , Quasiquoter.specs
  , Roundtrip.specs
  , Samples.specs
  , Verification.specs
  ]
