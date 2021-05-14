 
 /*------------------------------------------------------------------------
    File        : HS256
    Purpose     : 
    Syntax      : 
    Description : 

based on (https://knowledgebase.progress.com/articles/Knowledge/000043232):        
/* Simple HMAC function Overview                                                */
/* Developer: James Bowen                                                       */
/* Date:      13/06/2011                                                        */
/* References: http://www.ietf.org/rfc/rfc2104.txt                              */
/*             http://the.jhu.edu/upe/member_sites/zarfoss/HMAC-big.jpg         */
/*             http://en.wikipedia.org/wiki/HMAC                                */
/*             http://www.cryptostuff.com/crypto/index.php?title=hmac           */
/* HMAC is a hash based MAC algorithm defined in RFC 2104. It can use any       */
/* hash function (such as MD5, SHA1 etc). HMAC also requires a user             */
/* supplied secret key, which is a string of bytes of any length upto 64 bytes. */
        
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using Progress.Json.ObjectModel.JsonObject from propath.

block-level on error undo, throw.

class jwtoe.HS256: 
    method public static character signWithKey( input poHeader as JsonObject, input poPayload as JsonObject, input pcSecret as char ):
        def var cEncodedHeader as char no-undo.
        def var cEncodedPayload as char no-undo.
        def var cSignData as char no-undo.
        def var cSignature as char no-undo.
        
        cEncodedHeader = base64urlEncode(poHeader:GetJsonText()).
        cEncodedPayload = base64urlEncode(poPayload:GetJsonText()).
        cSignData = subst("&1.&2", cEncodedHeader, cEncodedPayload).
        
        return signWithKey(cSignData, pcSecret).
    end method.
    
    method public static character signWithKey ( input pcDataToSign as char, input pcSecret as char): 
        def var cSignature as char no-undo.
        
        cSignature = base64ToBase64Url(hmacBase64('SHA-256', pcSecret, pcDataToSign)).
        
        return pcDataToSign + "." + cSignature.
    end method.
    
     method private static int _binaryXOR (input intOperand1 as integer, input intOperand2 as integer):
        define variable iByteLoop  as integer no-undo.
        define variable iXOResult  as integer no-undo.
        define variable lFirstBit  as logical no-undo.
        define variable lSecondBit as logical no-undo.
    
        iXOResult = 0.
    
        /*spin through each byte of each char*/
        do iByteLoop = 0 to 7: /* as processing a single byte character */
    
            /*find state (true / false) of each integer's byte*/
            assign
                lFirstBit  = get-bits(intOperand1,iByteLoop + 1,1) = 1
                lSecondBit = get-bits(intOperand2,iByteLoop + 1,1) = 1.
    
            /* XOR each bit*/
            if (lFirstBit and not lSecondBit) or
                (lSecondBit and not lFirstBit) then
                iXOResult = iXOResult + EXP(2, iByteLoop).
        end.
     
        return iXOResult.
    end method. /*End function of BinaryXOR */

    method public static char hmacBase64 (input pcSHA as character, input pcKey as character, input pcData as character):
        define variable mKeyOpad       as memptr    no-undo.
        define variable mKeyIpad       as memptr    no-undo.
        define variable mData          as memptr    no-undo.
        define variable mKey           as memptr    no-undo.
        define variable mInnerCombined as memptr    no-undo.
        define variable mOuterCombined as memptr    no-undo.
        define variable iBytePos       as integer   no-undo.
        define variable iOpad          as integer   no-undo.
        define variable iIpad          as integer   no-undo.
        define variable iKey           as integer   no-undo.
        define variable iTimeTaken     as integer   no-undo.
        define variable rRawDataSHA    as raw       no-undo.
        define variable cHMACSHA       as character no-undo.
        
        &SCOPED-DEFINE xiBlockSize  64
        
        SET-SIZE(mKey)     = 0.
        SET-SIZE(mKeyOpad) = 0.
        SET-SIZE(mKeyIpad) = 0.
        SET-SIZE(mKey)     = {&xiBlockSize}.
        SET-SIZE(mKeyOpad) = {&xiBlockSize}.
        SET-SIZE(mKeyIpad) = {&xiBlockSize}.
        
        do iBytePos = 1 to {&xiBlockSize}:
            PUT-BYTES(mKey,     iBytePos) = hex-decode("00":U).  /* 64 bytes of zeros 0x00*/
            PUT-BYTES(mKeyOpad, iBytePos) = hex-decode("5C":U).  /* 64 bytes of 0x5C (92 dec,  "/" ascii) */
            PUT-BYTES(mKeyIpad, iBytePos) = hex-decode("36":U).  /* 64 bytes of 0x36 (54 dec, "6" ascii)*/
        end.
        
        /* correction by Valery A.Eliseev */
        if length(pcKey) > {&xiBlockSize} then 
        do:
            set-size(mData) = length(pcKey).
            put-string(mData, 1, length(pcKey)) = pcKey.
            rRawDataSHA = sha1-digest(mData).
            PUT-BYTES(mKey, 1) = rRawDataSHA.
        end.
        else
            /* end of correction */
        
            PUT-STRING(mKey, 1, length(pckey))  = pcKey. 
        
        do iBytePos = 1 to {&xiBlockSize}:
          
            assign
                iKey  = get-byte(mKey,     iBytePos)
                iOpad = get-byte(mKeyOpad, iBytePos)
                iIpad = get-byte(mKeyIpad, iBytePos).
          
            /* The inner key, mKeyIpad is formed from mKey by XORing each byte with 0x36.. */
            PUT-BYTE(mKeyIpad, iBytePos) = _binaryXOR(input iKey, 
                input iIpad).
        
            /* The inner key, mKeyOpad is formed from mKey by XORing each byte with 0x5C. */
            PUT-BYTE(mKeyOpad, iBytePos) = _binaryXOR(input iKey, 
                input iOpad).
        
        end.
        
        SET-SIZE(mKey)  = 0.
        SET-SIZE(mData) = 0.
        SET-SIZE(mData) = length(pcData).
        PUT-STRING(mData,1,length(pcData)) = pcData.
        
        
        /* Inner Loop*/
        SET-SIZE(mInnerCombined)      = get-size(mKeyIpad) + GET-SIZE(mData).
        
        PUT-BYTES(mInnerCombined, 1)  = mKeyIpad.
        SET-SIZE(mKeyIpad) = 0.
        
        /*Append the data the end of the block size.*/
        PUT-BYTES(mInnerCombined, {&xiBlockSize} + 1) = mData.
        
        /* Deallocates any memory. */
        SET-SIZE(mData) = 0.
        
        /* Get the results of the SHA Digest.*/
        case pcSHA:
            when 'SHA1' then
                assign
                    rRawDataSHA = sha1-digest(mInnerCombined).
            when 'SHA-256' then
                assign
                    rRawDataSHA = message-digest('SHA-256', mInnerCombined).
            otherwise 
            assign
                rRawDataSHA = sha1-digest(mInnerCombined).
        end case.
                                         
        /* Deallocates any memory. */
        SET-SIZE(mInnerCombined) = 0.
        
        /* Outer Loop calculation for SHA*/
        SET-SIZE(mOuterCombined)                      = 0.
        SET-SIZE(mOuterCombined)                      = get-size(mKeyOpad) + LENGTH(rRawDataSHA,'RAW':U).
        PUT-BYTES(mOuterCombined, 1)                  = mKeyOpad.
        PUT-BYTES(mOuterCombined, {&xiBlockSize} + 1) = rRawDataSHA.
        
        /* SHA*/
        case pcSHA:
            when 'SHA1' then
                assign
                    rRawDataSHA = sha1-digest(mOuterCombined).
            when 'SHA-256' then
                assign
                    rRawDataSHA = message-digest('SHA-256', mOuterCombined).
            otherwise 
            assign
                rRawDataSHA = sha1-digest(mOuterCombined).
        end case.
        
        /* Deallocates any memory. */
        SET-SIZE(mKeyOpad)       = 0.
        SET-SIZE(mOuterCombined) = 0.
        
        /* Convert the raw binary results into a human readable BASE-64 value.*/
        cHMACSHA = base64-encode(rRawDataSHA).
    /*    cHMACSHA = HEX-ENCODE(rRawDataSHA).*/
        
        
        &UNDEFINE xiBlockSize
        return cHMACSHA.
        
        finally:
            set-size(mKeyOpad      ) = 0.
            set-size(mKeyIpad      ) = 0.
            set-size(mData         ) = 0.
            set-size(mKey          ) = 0.
            set-size(mInnerCombined) = 0.
            set-size(mOuterCombined) = 0.
        end finally.
    end method. /** End Of Function HMACSHA1-BASE64 */
        
    method public static char base64urlEncode ( input cString as longchar ):
        DEF VAR cEncoded AS char NO-UNDO.
        DEF VAR mAuth AS memptr NO-UNDO.
        
        copy-lob from cString to mAuth.
        cEncoded = BASE64-ENCODE(mAuth).
          
        return base64ToBase64Url(cEncoded).
        
        finally:
            set-size(mAuth) = 0.            
        end finally.
    end method.
    
    method public static char base64UrlDecode ( input cBase64Url as longchar ):
        def var cDecoded as longchar no-undo.
        def var mAuth as memptr no-undo.
        def var cBase64 as char no-undo.
        
        cBase64 = base64UrlToBase64(cBase64Url).
        mAuth = base64-decode(cBase64).
        copy-lob from mAuth to cDecoded.
        
        return string(cDecoded).
        
        finally:
            set-size(mAuth) = 0.            
        end finally.
    end method.
    
    method public static char base64ToBase64Url ( input cBase64 as char ):
        cBase64 = trim(trim(cBase64, "="), "=").
        cBase64 = replace(cBase64, "+", "-").
        cBase64 = replace(cBase64, "/", "_").
    
        return cBase64.
    end method.
    
    method public static char base64UrlToBase64 ( input cBase64Url as longchar ):
        def var i as int no-undo.
        cBase64Url = replace(cBase64Url, "-", "+").
        cBase64Url = replace(cBase64Url, "_", "/").
        
        do i = 0 to 3:
           if length(cBase64Url) mod 4 <> 0
           then cBase64Url = cBase64Url + "=".
           else leave.
        end.    
            
        return string(cBase64Url).
    end method.

end class.