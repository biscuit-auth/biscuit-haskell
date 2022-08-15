{-|
  Module      : Auth.Biscuit.Utils
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
-}
module Auth.Biscuit.Utils
  ( maybeToRight
  , rightToMaybe
  ) where

-- | Exactly like `maybeToRight` from the `either` package,
-- but without the dependency footprint
maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right

-- | Exactly like `rightToMaybe` from the `either` package,
-- but without the dependency footprint
rightToMaybe :: Either b a -> Maybe a
rightToMaybe = either (const Nothing) Just
