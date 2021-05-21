module Auth.Biscuit.Utils
  ( maybeToRight
  ) where

maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right
