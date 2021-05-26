{-|
  Module      : Auth.Biscuit.Utils
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
-}
module Auth.Biscuit.Utils
  ( maybeToRight
  ) where

-- | Exactly like `maybeToRight` from the `either` package,
-- but without the dependency footprint
maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right
