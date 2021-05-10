# jwtoe
Small library to use JWT in Progress OpenEdge ABL

At the moment this library supports HS256.

API is similar to https://github.com/jwtk/jjwt.

## Create JWT token
```
using Progress.Lang.*.
using jwtoe.Jwt from propath.
using jwtoe.JwtBuilder from propath.
def var cJwtToken as char no-undo.


cJwtToken = Jwt:builder()
            :setAudience("audience")
            :setIssuer("issuer")
            :setSubject("subject")
            :setClaim("key", "value")
            :setExpiresInSeconds(60)
            :signWithHS256Key("mySecretKey")
            :compact().
```           
            
## Validate JWT token  
```
using Progress.Lang.*.
using jwtoe.Jwt from propath.
using jwtoe.JwtError from propath.

def var cReceivedToken as char no-undo.
cReceivedToken = "some value".
        
do on error undo, throw:
    Jwt:parseBuilder()
       :setSigningKeyHS256("mySecretKey")
       :parseClaimsJws(cReceivedToken).
    
    // here you are sure that token was valid
    
    catch e as JwtError:
        message e:GetMessageNum(1) skip e:GetMessage(1) view-as alert-box title "JWT error".
    end catch.
end.
```

## Using values from the received JWT token
```
using Progress.Lang.*.
using jwtoe.Jwt from propath.
using jwtoe.JwtError from propath.

def var oClaims as JsonObject no-undo.
def var cReceivedToken as char no-undo.
cReceivedToken = "some value".
        
do on error undo, throw:
    oClaims = Jwt:parseBuilder()
                 :setSigningKeyHS256("mySecretKey")
                 :parseClaimsJws(cReceivedToken).
    
    // here you are sure that token was valid
    message oClaims:GetCharacter("iss")).
    message oClaims:GetCharacter("aud")).
    message oClaims:GetCharacter("sub")).
    message oClaims:GetCharacter("key")).
    
    catch e as JwtError:
        message e:GetMessageNum(1) skip e:GetMessage(1) view-as alert-box title "JWT error".
    end catch.
end.
```

