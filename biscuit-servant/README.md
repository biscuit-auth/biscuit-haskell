<img src="https://raw.githubusercontent.com/divarvel/biscuit-haskell/main/assets/biscuit-logo.png" align=right>

# biscuit-servant 🤖 [![Hackage][hackage]][hackage-url]

> **Servant combinators to enable biscuit validation in your API trees**

## Usage

```Haskell
type AppM = WithVerifier Handler
type API = RequireBiscuit :> ProtectedAPI

-- /users
-- /users/:userId
type ProtectedAPI =
  "users" :> ( Get '[JSON] [User]
             :<|> Capture "userId" Int :> Get '[JSON] User
             )
app :: PublicKey -> Application
app pk = serveWithContext @API Proxy (genBiscuitCxt pk) server

server :: Server API
server biscuit =
  let handlers = userListHandler :<|> singleUserHandler
      handleAuth =
        handleBiscuit biscuit
        -- `allow if right(#authority, #admin);` will be the first policy
        -- for every endpoint policies added by endpoints (or sub-apis) will
        -- be appended.
        . withPriorityVerifier [verifier|allow if right(#authority, #admin);|]
        -- `deny if true;` will be the last policy for every endpoint
        -- policies added by endpoints (or sub-apis) will be prepended.
        . withFallbackVerifier [verifier|deny if true;|]
  in hoistServer @ProtectedAPI Proxy handleAuth handlers

allUsers :: [User]
allUsers = [ User 1 "Danielle" "George"
           , User 2 "Albert" "Einstein"
           ]

userListHandler :: AppM [User]
userListHandler = withVerifier [verifier|allow if right(#authority, #userList)|]
  $ pure allUsers

singleUserHandler :: Int -> AppM User
singleUserHandler uid =
  withVerifier [verifier|allow if right(#authority, #getUser, ${uid})|] $
  let user = find (\user -> userId user == uid) allUsers
   in maybe (throwError error404) (\user -> pure user) user
```

[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-servant
