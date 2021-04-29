module Spec where

import           Test.Tasty

import qualified Spec.Parser as Parser

main :: IO ()
main = defaultMain $ testGroup "biscuit-haskell"
  [ Parser.specs
  ]
