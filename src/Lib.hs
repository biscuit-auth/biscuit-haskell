module Lib
    ( someFunc
    ) where

import           Biscuit
import           Control.Monad          (when)
import           Data.ByteString.Base64

someFunc :: IO ()
someFunc = do
  let kp = keypairNew "abcdefghabcdefghabcdefghabcdefgh"
  print kp
  let pub = keypairPublic kp
  print pub
  let builder = biscuitBuilder kp
  res <- biscuitBuilderAddAuthorityFact builder "right(#efgh)"
  print res
  when (not res) $ do
    print "fact error"
    print =<< getErrorMessage
  res' <- biscuitBuilderAddAuthorityCaveat builder "*yolo(#aa) <- right(#authority,#efgh)"
  print res'
  when (not res') $ do
    print "caveat error"
    print =<< getErrorMessage
  print builder
  let bisc = biscuitBuilderBuild builder "abcdefghabcdefghabcdefghabcdefgh"
  print bisc
  print =<< encodeBase64 <$> serialize bisc
  let verif = biscuitVerify bisc pub
  res'' <- verifierAddCaveat verif "*right(#abcd) <- right(#authority,#efgh)"
  print res''
  putStrLn (verifierPrint verif)
  let vRes = verifierVerify verif
  print vRes
