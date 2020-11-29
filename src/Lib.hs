module Lib
    ( someFunc
    ) where

import           Biscuit
import           Control.Monad (when)

someFunc :: IO ()
someFunc = do
  let kp = keypairNewPrint "abcdefghabcdefghabcdefghabcdefgh"
  print kp
  let pub = keypairPublic kp
  print pub
  let builder = biscuitBuilder kp
  res <- biscuitBuilderAddAuthorityFact builder "right(#efgh)"
  print res
  when (not res) $ do
    print "fact error"
    print =<< errorMessage
  res' <- biscuitBuilderAddAuthorityCaveat builder "*cav() <- user_id($id)"
  print res'
  when (not res') $ do
    print "caveat error"
    print =<< errorMessage
  print builder
  let bisc = biscuitBuilderBuild builder "abcdefghabcdefghabcdefghabcdefgh"
  print bisc
  let verif = biscuitVerify bisc pub
  res'' <- verifierAddCaveat verif "*right(#abcd) <- right(#authority,#efgh)"
  print res''
  putStrLn (verifierPrint verif)
  let vRes = verifierVerify verif
  print vRes
