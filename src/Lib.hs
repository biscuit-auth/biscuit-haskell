{-# LANGUAGE ForeignFunctionInterface #-}

module Lib
    ( someFunc
    ) where


import Foreign.C
import Foreign.Ptr (Ptr.nullPtr)

foreign import ccall "" c_keypair_new :: CDouble -> CDouble

someFunc :: IO ()
someFunc = putStrLn "someFunc"
