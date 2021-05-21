{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.Crypto (specs) where

import           Data.ByteString             (ByteString)
import           Data.List.NonEmpty          (NonEmpty ((:|)))
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.Parser (block)
import qualified Auth.Biscuit.Sel            as Sel
import           Auth.Biscuit.Token          (Biscuit (..))

specs :: TestTree
specs = testGroup "biscuit crypto"
  [ testGroup "signature algorithm"
      [ singleBlockRoundtrip
      , multiBlockRoundtrip
      , tamperedAuthority
      , tamperedBlock
      ]
  , testGroup "high-level functions"
      [ singleBlockRoundtrip'
      , multiBlockRoundtrip'
      , tamperedAuthority'
      , tamperedBlock'
      ]
  ]

singleBlockRoundtrip :: TestTree
singleBlockRoundtrip = testCase "Single block roundtrip" $ do
  rootKp <- newKeypair
  let pub = publicKey rootKp
      content = "content"
      token = (pub, content) :| []
  sig <- Sel.signBlock rootKp content
  result <- Sel.verifySignature token sig
  result @?= True

multiBlockRoundtrip :: TestTree
multiBlockRoundtrip = testCase "Multi block roundtrip" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token = (pub, content) :| [(pub', content')]
  sig    <- Sel.signBlock kp content
  sig'   <- Sel.aggregate sig =<< Sel.signBlock kp' content'
  result <- Sel.verifySignature token sig'
  result @?= True

tamperedAuthority :: TestTree
tamperedAuthority = testCase "Tampered authority" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token  = (pub, "modified") :| []
      token' = (pub, "modified") :| [(pub', content')]
  sig    <- Sel.signBlock kp content
  sig'   <- Sel.aggregate sig =<< Sel.signBlock kp' content'
  result <- Sel.verifySignature token sig'
  result @?= False
  result' <- Sel.verifySignature token' sig'
  result' @?= False

tamperedBlock :: TestTree
tamperedBlock = testCase "Tampered block" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token = (pub, content) :| [(pub', "modified")]
  sig    <- Sel.signBlock kp content
  sig'   <- Sel.aggregate sig =<< Sel.signBlock kp' content'
  result <- Sel.verifySignature token sig'
  result @?= False

singleBlockRoundtrip' :: TestTree
singleBlockRoundtrip' = testCase "Single block roundtrip" $ do
  rootKp <- newKeypair
  let pub = publicKey rootKp
  b <- mkBiscuit rootKp [block|right(#authority,#read);|]
  result <- checkBiscuitSignature b pub
  result @?= True

multiBlockRoundtrip' :: TestTree
multiBlockRoundtrip' = testCase "Multi block roundtrip" $ do
  kp <- newKeypair
  let pub = publicKey kp
  b <- mkBiscuit kp [block|right(#authority,#read);|]
  b' <- addBlock [block|check if true;|] b
  result <- checkBiscuitSignature b' pub
  result @?= True

tamper :: (PublicKey, (ByteString, Block))
       -> (PublicKey, (ByteString, Block))
tamper (pk, (_, b)) = (pk, ("tampered", b))

tamperedAuthority' :: TestTree
tamperedAuthority' = testCase "Tampered authority" $ do
  kp <- newKeypair
  let pub = publicKey kp
  b <- mkBiscuit kp [block|right(#authority,#read);|]
  b' <- addBlock [block|check if true;|] b
  let modified = b'
        { authority = tamper $ authority b
        }
  result <- checkBiscuitSignature modified pub
  result @?= False

tamperedBlock' :: TestTree
tamperedBlock' = testCase "Tampered block" $ do
  kp <- newKeypair
  let pub = publicKey kp
  b <- mkBiscuit kp [block|right(#authority,#read);|]
  b' <- addBlock [block|check if true;|] b
  let modified = b'
        { blocks = tamper <$> blocks b
        }
  result <- checkBiscuitSignature modified pub
  result @?= False
