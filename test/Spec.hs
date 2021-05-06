module Spec where

import           Test.Tasty

import qualified Spec.Crypto   as Crypto
import qualified Spec.Executor as Executor
import qualified Spec.Parser   as Parser

main :: IO ()
main = defaultMain $ testGroup "biscuit-haskell"
  [ Crypto.specs
  , Executor.specs
  , Parser.specs
  ]
