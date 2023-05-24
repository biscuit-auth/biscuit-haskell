module Web.Twain.Biscuit () where

import Web.Twain (ResponderM)
import Auth.Biscuit 

biscuit :: ResponderM (Biscuit OpenOrSealed Verified)
biscuit = undefined