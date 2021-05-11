 
 /*------------------------------------------------------------------------
    File        : JwtBuilder
    Purpose     : 
    Syntax      : 
    Description : JSON Wet Token builder for Progress OpenEdge
    Author(s)   : Valdemar Sinkievič (valdemar@bpm-id.com)
    Created     : Mon May 10 09:41:37 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using Progress.Json.ObjectModel.JsonObject from propath.
using jwtoe.JwtBuilder from propath.
using jwtoe.HS256 from propath.

block-level on error undo, throw.

class jwtoe.JwtBuilder: 
    def var oHeader as JsonObject no-undo.
    def var oPayload as JsonObject no-undo.
    def var cHS256key as char no-undo.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/
        
    constructor public JwtBuilder (  ):
        super ().
        oHeader = new JsonObject(). 
        oPayload = new JsonObject().
    //    oJsonHeaderObject:Add("typ", "JWT").
    end constructor.
    
    method public JwtBuilder setSubject (pcSubject as char): 
        oPayload:Add("sub", pcSubject).
        return this-object.
    end method.

    method public JwtBuilder setIssuer (pcIssuer as char): 
        oPayload:Add("iss", pcIssuer).
        return this-object.
    end method.
    
    method public JwtBuilder setAudience (pcAudience as char): 
        oPayload:Add("aud", pcAudience).
        return this-object.
    end method. 

    method public JwtBuilder setClaim(pcKey as char, pcValue as char): 
        oPayload:Add(pcKey, pcValue).
        return this-object.
    end method.
    
    method public JwtBuilder setExpiresInSeconds(piSeconds as int): 
        oPayload:Add("exp", _getCurrentTime() + piSeconds).
        return this-object.
    end method.
    
    method protected int64 _getCurrentTime():
        DEFINE VARIABLE vDateOrDateTime AS DATETIME NO-UNDO INITIAL 1/1/1970.
        
        return interval(datetime-tz(today, mtime),vDateOrDateTime, "seconds" ) - timezone * 60.
    end method.
    
    method public character compact ():
        def var cToken as char no-undo.
        
        cToken = HS256:signWithKey(oHeader, oPayload, cHS256key).
        delete object(oHeader).
        delete object(oPayload).
        return cToken.
    end method.
    
    method public JwtBuilder signWithHS256Key (pcKey as char):
        oHeader:Add("alg", "HS256").
        cHS256key = pcKey.
        return this-object.
    end method.
end class.