 
 /*------------------------------------------------------------------------
    File        : JwtParser
    Purpose     : Used to verify received JWT token
    Syntax      : 
    Description : 
    Author(s)   : Valdemar Sinkievič (valdemar@bpm-id.com)
    Created     : Mon May 10 11:20:17 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using Progress.Json.ObjectModel.JsonObject from propath.
using jwtoe.JwtParser from propath.
using jwtoe.JwtError from propath.
using jwtoe.HS256 from propath.
using Progress.Json.ObjectModel.ObjectModelParser from propath.

block-level on error undo, throw.

class jwtoe.JwtParser: 
    def var cSigningKey as char no-undo.
    
    def protected static var jsonParser as ObjectModelParser no-undo init ?.
    
    method public JwtParser setSigningKeyHS256 (pcSecretKey as char):
        if pcSecretKey = ? or pcSecretKey = ""
        then undo, throw new JwtError("Key was not provided!", 2).
        
        cSigningKey = pcSecretKey. 
        return this-object.
    end method. 
    
    method public JsonObject parseClaimsJws (pcReceivedToken as char):
        def var claims as JsonObject no-undo.
        def var cDataToSign as char no-undo.
        def var cPayloadJson as char no-undo.
        def var iValidUntilTime as int64 no-undo.
     //   def var cReceivedSignature as char no-undo.
        
        if pcReceivedToken = ? or pcReceivedToken = ""
        then undo, throw new JwtError("JWT token was not provided!", 1).
        
        if num-entries(pcReceivedToken, ".") <> 3
        then undo, throw new JwtError("Wrong JWT token format!", 3).
        
        cDataToSign = subst("&1.&2", entry(1, pcReceivedToken, "."), entry(2, pcReceivedToken, ".")).
   //     cReceivedSignature = entry(3, pcReceivedToken, ".").
        
        if pcReceivedToken <> HS256:signWithKey(cDataToSign, cSigningKey)
        then undo, throw new JwtError("Wrong signature!", 4).

        if jwtoe.JwtParser:jsonParser = ?
        then jwtoe.JwtParser:jsonParser = new ObjectModelParser().
        
        cPayloadJson = HS256:base64UrlDecode(entry(2, pcReceivedToken, ".")).
        claims = cast(jwtoe.JwtParser:jsonParser:parse(cPayloadJson), JsonObject).
        
        if claims:Has("exp")
        then do:
            iValidUntilTime = claims:GetInt64("exp").
            if  iValidUntilTime <> ? and iValidUntilTime < _getCurrentTime()
            then undo, throw new JwtError("Token expired!", 5).
        end.
        return claims.
    end.

    method protected int64 _getCurrentTime():
        DEFINE VARIABLE vDateOrDateTime AS DATETIME NO-UNDO INITIAL 1/1/1970.
        
        return interval(datetime-tz(today, mtime),vDateOrDateTime, "seconds" ) - timezone * 60.
    end method.
end class.