{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedLists            #-}
{-# LANGUAGE OverloadedStrings          #-}
module Auth.Biscuit.Symbols
  ( Symbols
  , BlockSymbols
  , ReverseSymbols
  , SymbolRef (..)
  , getSymbol
  , addSymbols
  , addFromBlock
  , addFromBlocks
  , reverseSymbols
  , getSymbolList
  , getSymbolCode
  , newSymbolTable
  ) where

import           Control.Monad      (join)
import           Data.Int           (Int64)
import           Data.Map           (Map, elems, (!?))
import qualified Data.Map           as Map
import           Data.Set           (Set, difference, union)
import qualified Data.Set           as Set
import           Data.Text          (Text)

import           Auth.Biscuit.Utils (maybeToRight)

newtype SymbolRef = SymbolRef { getSymbolRef :: Int64 }
  deriving stock (Eq)

instance Show SymbolRef where
  show = ("#" <>) . show . getSymbolRef

newtype Symbols = Symbols { getSymbols :: Map Int64 Text }
  deriving stock (Eq, Show)

newtype BlockSymbols = BlockSymbols { getBlockSymbols :: Map Int64 Text }
  deriving stock (Eq, Show)
  deriving newtype (Semigroup)

newtype ReverseSymbols = ReverseSymbols { getReverseSymbols :: Map Text Int64 }
  deriving stock (Eq, Show)
  deriving newtype (Semigroup)

getSymbol :: Symbols -> SymbolRef -> Either String Text
getSymbol (Symbols m) (SymbolRef i) =
  maybeToRight ("Missing symbol at id #" <> show i) $ m !? i

-- | Given already existing symbols and a set of symbols used in a block,
-- compute the symbol table carried by this specific block
addSymbols :: Symbols -> Set Text -> BlockSymbols
addSymbols (Symbols m) symbols =
  let existingSymbols = Set.fromList (elems commonSymbols) `union` Set.fromList (elems m)
      newSymbols = Set.toList $ symbols `difference` existingSymbols
      starting = fromIntegral $ 1024 + (Map.size m - Map.size commonSymbols)
   in BlockSymbols $ Map.fromList (zip [starting..] newSymbols)

getSymbolList :: BlockSymbols -> [Text]
getSymbolList (BlockSymbols m) = Map.elems m

newSymbolTable :: Symbols
newSymbolTable = Symbols commonSymbols

-- | Given the symbol table of a protobuf block, update the provided symbol table
addFromBlock :: Symbols -> BlockSymbols -> Symbols
addFromBlock (Symbols m) (BlockSymbols bm) =
   Symbols $ m <> bm

-- | Compute a global symbol table from a series of block symbol tables
addFromBlocks :: [[Text]] -> Symbols
addFromBlocks blocksTables =
  let allSymbols = join blocksTables
   in Symbols $ commonSymbols <> Map.fromList (zip [1024..] allSymbols)

-- | Reverse a symbol table
reverseSymbols :: Symbols -> ReverseSymbols
reverseSymbols =
  let swap (a,b) = (b,a)
   in ReverseSymbols . Map.fromList . fmap swap . Map.toList . getSymbols

-- | Given a reverse symbol table (symbol refs indexed by their textual
-- representation), turn textual representations into symbol refs.
-- This function is partial, the reverse table is guaranteed to
-- contain the expected textual symbols.
getSymbolCode :: ReverseSymbols -> Text -> SymbolRef
getSymbolCode (ReverseSymbols rm) t = SymbolRef $ rm Map.! t

-- | The common symbols defined in the biscuit spec
commonSymbols :: Map Int64 Text
commonSymbols = Map.fromList $ zip [0..]
  [ "read"
  , "write"
  , "resource"
  , "operation"
  , "right"
  , "time"
  , "role"
  , "owner"
  , "tenant"
  , "namespace"
  , "user"
  , "team"
  , "service"
  , "admin"
  , "email"
  , "group"
  , "member"
  , "ip_address"
  , "client"
  , "client_ip"
  , "domain"
  , "path"
  , "version"
  , "cluster"
  , "node"
  , "hostname"
  , "nonce"
  , "query"
  ]
