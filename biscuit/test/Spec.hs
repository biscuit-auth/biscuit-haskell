module Main (main) where

import           Test.Tasty

import qualified Spec.Executor       as Executor
import qualified Spec.NewCrypto      as NewCrypto
import qualified Spec.Parser         as Parser
import qualified Spec.Quasiquoter    as Quasiquoter
import qualified Spec.RevocationIds  as RevocationIds
import qualified Spec.Roundtrip      as Roundtrip
import qualified Spec.SampleReader   as SampleReader
import qualified Spec.ScopedExecutor as ScopedExecutor
import qualified Spec.Verification   as Verification

main :: IO ()
main = do
  sampleReader <- SampleReader.getSpecs
  defaultMain $ testGroup "biscuit-haskell"
    [
      NewCrypto.specs
    , Executor.specs
    , Parser.specs
    , Quasiquoter.specs
    , RevocationIds.specs
    , Roundtrip.specs
    , Verification.specs
    , ScopedExecutor.specs
    , sampleReader
    ]
