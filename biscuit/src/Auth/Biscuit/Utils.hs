{-# LANGUAGE CPP #-}

-- |
--  Module      : Auth.Biscuit.Utils
--  Copyright   : © Clément Delafargue, 2021
--  License     : MIT
--  Maintainer  : clement@delafargue.name
module Auth.Biscuit.Utils
  ( maybeToRight,
    rightToMaybe,
    encodeHex,
    encodeHex',
    decodeHex,
  )
where

#if MIN_VERSION_base16(1,0,0)
import qualified Data.Base16.Types as Hex
#endif
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as Hex
import Data.Text (Text)

encodeHex :: ByteString -> Text
#if MIN_VERSION_base16(1,0,0)
encodeHex = Hex.extractBase16 . Hex.encodeBase16
#else
encodeHex = Hex.encodeBase16
#endif

encodeHex' :: ByteString -> ByteString
#if MIN_VERSION_base16(1,0,0)
encodeHex' = Hex.extractBase16 . Hex.encodeBase16'
#else
encodeHex' = Hex.encodeBase16'
#endif

decodeHex :: ByteString -> Either Text ByteString
#if MIN_VERSION_base16(1,0,0)
decodeHex = Hex.decodeBase16Untyped
#else
decodeHex = Hex.decodeBase16
#endif

-- | Exactly like `maybeToRight` from the `either` package,
-- but without the dependency footprint
maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right

-- | Exactly like `rightToMaybe` from the `either` package,
-- but without the dependency footprint
rightToMaybe :: Either b a -> Maybe a
rightToMaybe = either (const Nothing) Just
