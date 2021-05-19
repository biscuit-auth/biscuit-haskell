{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE TypeApplications      #-}

module Proto
  ( Biscuit (..)
  , Signature (..)
  , Block (..)
  , FactV1 (..)
  , RuleV1 (..)
  , CheckV1 (..)
  , PredicateV1 (..)
  , IDV1 (..)
  , ExpressionV1 (..)
  , IDSet (..)
  , Op (..)
  , OpUnary (..)
  , UnaryKind (..)
  , OpBinary (..)
  , BinaryKind (..)
  , getField
  , putField
  , decodeBlockList
  , decodeBlock
  , encodeBlockList
  , encodeBlock

  --
  , decodeCBiscuit
  , decodeBiscuit
  , decodeAuthority
  , decoded
  , toto
  , v1Test
  , v1Test'
  , v1Test''
  , allSamples
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as ByteString
import           Data.ByteString.Base64
import           Data.Int
import           Data.ProtocolBuffers
import           Data.Serialize
import           Data.Text
import           GHC.Generics           (Generic)
import           Validation

data Biscuit = Biscuit
  { authority :: Required 1 (Value ByteString)
  , blocks    :: Repeated 2 (Value ByteString)
  , keys      :: Repeated 3 (Value ByteString)
  , signature :: Required 4 (Message Signature)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data CBiscuit = CBiscuit
  { cAuthority :: Required 1 (Message Block)
  , cBlocks    :: Repeated 2 (Message Block)
  , cKeys      :: Repeated 3 (Value ByteString)
  , cSignature :: Required 4 (Message Signature)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data SealedBiscuit = SealedBiscuit
  { sAuthority :: Required 1 (Value ByteString)
  , sBlocks    :: Repeated 2 (Value ByteString)
  , sSignature :: Required 3 (Value ByteString)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data Signature = Signature
  { parameters :: Repeated 1 (Value ByteString)
  , z          :: Required 2 (Value ByteString)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data Block = Block {
    index     :: Required 1 (Value Int32)
  , symbols   :: Repeated 2 (Value Text)
  -- , facts_v0   :: Repeated 3 (Message FactV0)
  -- , rules_v0   :: Repeated 4 (Message RuleV0)
  -- , caveats_v0 :: Repeated 5 (Message CaveatV0)
  , context   :: Optional 6 (Value Text)
  , version   :: Optional 7 (Value Int32)
  , facts_v1  :: Repeated 8 (Message FactV1)
  , rules_v1  :: Repeated 9 (Message RuleV1)
  , checks_v1 :: Repeated 10 (Message CheckV1)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype FactV1 = FactV1
  { predicate :: Required 1 (Message PredicateV1)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data RuleV1 = RuleV1
  { head        :: Required 1 (Message PredicateV1)
  , body        :: Repeated 2 (Message PredicateV1)
  , expressions :: Repeated 3 (Message ExpressionV1)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype CheckV1 = CheckV1
  { queries :: Repeated 1 (Message RuleV1)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data PredicateV1 = PredicateV1
  { name :: Required 1 (Value Int64)
  , ids  :: Repeated 2 (Message IDV1)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data IDV1 =
    IDSymbol (Required 1 (Value Int64))
  | IDVariable (Required 2 (Value Int32))
  | IDInteger (Required 3 (Value Int64))
  | IDString (Required 4 (Value Text))
  | IDDate (Required 5 (Value Int64))
  | IDBytes (Required 6 (Value ByteString))
  | IDBool (Required 7 (Value Bool))
  | IDIDSet (Required 8 (Message IDSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)


newtype IDSet = IDSet
  { set :: Repeated 1 (Message IDV1)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

type CV1Id = Required 1 (Value Int32)
data ConstraintV1 =
    CV1Int    CV1Id (Required 2 (Message IntConstraintV1))
  | CV1String CV1Id (Required 3 (Message StringConstraintV1))
  | CV1Date   CV1Id (Required 4 (Message DateConstraintV1))
  | CV1Symbol CV1Id (Required 5 (Message SymbolConstraintV1))
  | CV1Bytes  CV1Id (Required 6 (Message BytesConstraintV1))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data IntConstraintV1 =
    ICV1LessThan       (Required 1 (Value Int64))
  | ICV1GreaterThan    (Required 2 (Value Int64))
  | ICV1LessOrEqual    (Required 3 (Value Int64))
  | ICV1GreaterOrEqual (Required 4 (Value Int64))
  | ICV1Equal          (Required 5 (Value Int64))
  | ICV1InSet          (Required 6 (Message IntSet))
  | ICV1NotInSet       (Required 7 (Message IntSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype IntSet = IntSet
  { set :: Packed 7 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data StringConstraintV1 =
    SCV1Prefix   (Required 1 (Value Text))
  | SCV1Suffix   (Required 2 (Value Text))
  | SCV1Equal    (Required 3 (Value Text))
  | SCV1InSet    (Required 4 (Message StringSet))
  | SCV1NotInSet (Required 5 (Message StringSet))
  | SCV1Regex    (Required 6 (Value Text))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype StringSet = StringSet
  { set :: Repeated 1 (Value Text)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data DateConstraintV1 =
    DCV1Before (Required 1 (Value Int64))
  | DCV1After  (Required 2 (Value Int64))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data SymbolConstraintV1 =
    SyCV1InSet    (Required 1 (Message SymbolSet))
  | SyCV1NotInSet (Required 2 (Message SymbolSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype SymbolSet = SymbolSet
  { set :: Packed 1 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)


data BytesConstraintV1 =
    BCV1Equal    (Required 1 (Value ByteString))
  | BCV1InSet    (Required 2 (Message BytesSet))
  | BCV1NotInSet (Required 3 (Message BytesSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype BytesSet = BytesSet
  { set :: Repeated 1 (Value ByteString)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype ExpressionV1 = ExpressionV1
  { ops :: Repeated 1 (Message Op)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data Op =
    OpVValue  (Required 1 (Message IDV1))
  | OpVUnary  (Required 2 (Message OpUnary))
  | OpVBinary (Required 3 (Message OpBinary))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data UnaryKind = Negate | Parens | Length
  deriving stock (Show, Enum, Bounded)

newtype OpUnary = OpUnary
  { kind :: Required 1 (Enumeration UnaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data BinaryKind =
    LessThan
  | GreaterThan
  | LessOrEqual
  | GreaterOrEqual
  | Equal
  | Contains
  | Prefix
  | Suffix
  | Regex
  | Add
  | Sub
  | Mul
  | Div
  | And
  | Or
  | Intersection
  | Union
  deriving stock (Show, Enum, Bounded)

newtype OpBinary = OpBinary
  { kind :: Required 1 (Enumeration BinaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data PolicyKind = Allow | Deny
  deriving stock (Show, Enum, Bounded)

data Policy = Policy
  { queries :: Repeated 1 (Message RuleV1)
  , kind    :: Required 2 (Enumeration PolicyKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data VerifierPolicies = VerifierPolicies
  { symbols  :: Repeated 1 (Value Text)
  , version  :: Optional 2 (Value Int32)
  , facts    :: Repeated 3 (Message FactV1)
  , rules    :: Repeated 4 (Message RuleV1)
  , checks   :: Repeated 5 (Message CheckV1)
  , policies :: Repeated 6 (Message Policy)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

decodeBlockList :: ByteString
                -> Either String Biscuit
decodeBlockList = runGet decodeMessage

decodeBlock :: ByteString
            -> Either String Block
decodeBlock = runGet decodeMessage

encodeBlockList :: Biscuit -> ByteString
encodeBlockList = runPut . encodeMessage

encodeBlock :: Block -> ByteString
encodeBlock = runPut . encodeMessage


decodeBiscuit :: ByteString
              -> Either String Biscuit
decodeBiscuit = runGet decodeMessage . decodeBase64Lenient

decodeAuthority :: ByteString
                -> Either String Block
decodeAuthority = runGet decodeMessage


decodeCBiscuit :: ByteString
              -> Either String CBiscuit
decodeCBiscuit = runGet decodeMessage

decoded :: Biscuit
decoded = either undefined id $ decodeBiscuit "CqYBCAASBnVzZXJJZBIOcmVhZE9ubHlBY2Nlc3MSCnJlc291cmNlSWQSBHJlYWQSBnVzZXJpZBoQCg4IBxIECAAQABIECAIgeypeClwKDggIEgQIARgJEgQIARgHEg4IAxIECAAQARIECAAQChIOCAISBAgAEAESBAgBGAkSDggHEgQIABAAEgQIARgHEhoIBBIECAAQABIECAEYCxIECAEYCRIECAAQChog/Be2qmYgERRHvdH/IN/Z5AAWSCFDjkSNXLZEvdNBY3QiRAogdNr/SGkItGP0piqRIQSXI2k1vZFrYOBQJf1mD71oZlgSICDINewl2TXZmtLDrGQVQhzz8YMbsmTai2rjk5ky7uIL"

toto :: ByteString
toto =
  let Biscuit{authority} = decoded
   in getField authority

v1Test :: FilePath -> IO (Block, [Block])
v1Test path = do
  let orFail = either (fail . show) pure
  ser <- ByteString.readFile path
  CBiscuit{cAuthority,cBlocks} <- orFail $ runGet decodeMessage ser
  pure (getField cAuthority, getField cBlocks)

v1Test'' :: FilePath -> IO ()
v1Test'' path = do
  let isOk _ = print (path, "ok" :: Text)
      isError _ = print (path, "error" :: Text)
  ser <- ByteString.readFile path
  either isError isOk $ runGet (decodeMessage @CBiscuit) ser

v1Test' :: FilePath -> IO ()
v1Test' path = do
  let orFail = either (fail . show) pure
  ser <- ByteString.readFile path
  Biscuit{authority,blocks} <- orFail $ runGet decodeMessage ser
  putStrLn "outer biscuit ok"
  print @Block =<< orFail (runGet decodeMessage (getField authority))
  putStrLn "authority ok"
  let decBlock = eitherToValidation . runGet (decodeMessage @Block)
      -- decBlocks = validationToEither $ traverse decBlock (getField blocks)
  print blocks
  print (decBlock <$> getField blocks)
  putStrLn "blocks ok"
  -- pure (getField authority, getField blocks)
  --
  --
allSamples :: [FilePath]
allSamples = ("../biscuit/samples/v1/" <>) <$>
 [ "test1_basic.bc"
 , "test2_different_root_key.bc"
 , "test3_invalid_signature_format.bc"
 , "test4_random_block.bc"
 , "test5_invalid_signature.bc"
 , "test6_reordered_blocks.bc"
 , "test7_invalid_block_fact_authority.bc"
 , "test8_invalid_block_fact_ambient.bc"
 , "test9_expired_token.bc"
 , "test10_authority_rules.bc"
 , "test11_verifier_authority_caveats.bc"
 , "test12_authority_caveats.bc"
 , "test13_block_rules.bc"
 , "test14_regex_constraint.bc"
 , "test15_multi_queries_caveats.bc"
 , "test16_caveat_head_name.bc"
 , "test17_expressions.bc"
 ]
