 
 /*------------------------------------------------------------------------
    File        : JwtParserTest
    Purpose     : 
    Syntax      : 
    Description : 
    Author(s)   : vsink_000
    Created     : Mon May 10 14:41:09 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using jwtoe.Jwt from propath.
using OpenEdge.Core.Assert from propath.
using Progress.Json.ObjectModel.JsonObject from propath.
using jwtoe.JwtError from propath.

block-level on error undo, throw.

class jwtoe.JwtParserTest:
    
       /*------------------------------------------------------------------------------
            Purpose:                                                                        
            Notes:                                                                        
    ------------------------------------------------------------------------------*/

    @Before.
    method public void setUpBeforeClass(  ):
        
        return.

    end method.
    
    /*------------------------------------------------------------------------------
            Purpose:                                                                        
            Notes:                                                                        
    ------------------------------------------------------------------------------*/
   
    @Setup.
    method public void setUp(  ):
        
        return.

    end method.
    
    @Test.
    method public void testTokenIsValid (): 
        // given
        def var lParsedSuccessfully as log init false.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
                :setSigningKeyHS256("mySecretKey")
                :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
        end.
        
        // then
        Assert:IsTrue(lParsedSuccessfully).
    end method.

    @Test.
    method public void testParsedClaims(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var cReceivedToken as char no-undo.
        def var oClaims as JsonObject no-undo.
        cReceivedToken = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI".
        
        // when
        do on error undo, throw:
            oClaims = Jwt:parseBuilder()
                         :setSigningKeyHS256("mySecretKey")
                         :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
        end.
        
        // then
        Assert:IsTrue(lParsedSuccessfully).
        Assert:NotNull(oClaims).
        Assert:equals("issuer", oClaims:GetCharacter("iss")).
        Assert:equals("audience", oClaims:GetCharacter("aud")).
        Assert:equals("subject", oClaims:GetCharacter("sub")).
        Assert:equals("value", oClaims:GetCharacter("key")).
        
    end method.

    @Test.
    method public void testErrorWhenTokenIsNull(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = ?.
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("mySecretKey")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.

    @Test.
    method public void testErrorWhenTokenIsEmpty(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = ?.
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("mySecretKey")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.
 
    @Test.
    method public void testErrorTokenIsWrong(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "wrong".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("mySecretKey")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.

    @Test.
    method public void testErrorTokenIsWrong2(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "xxx.xxx.xxx".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("mySecretKey")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.

    @Test.
    method public void testErrorWhenKeyIsWronk(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("badKey")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.

    @Test.
    method public void testErrorWhenKeyIsEmpty(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256(?)
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.
 
    @Test.
    method public void testErrorWhenKeyIsNull(): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI".
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
               :setSigningKeyHS256("")
               :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).        
    end method.

    @Test.
    method public void testTokenWithExpireTimeIsValid (): 
        // given
        def var lParsedSuccessfully as log init false.
        def var cReceivedToken as char no-undo.
        cReceivedToken = Jwt:builder():setExpiresInSeconds(1):signWithHS256Key("mySecretKey"):compact().
        
        // when
        do on error undo, throw:
            Jwt:parseBuilder()
                :setSigningKeyHS256("mySecretKey")
                :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
        end.
        
        // then
        Assert:IsTrue(lParsedSuccessfully).
    end method.

    @Test.
    method public void testTokenWithExpireTimeIsExpired (): 
        // given
        def var lParsedSuccessfully as log init false.
        def var lErrorcaught as log no-undo init false.
        def var cErrorMessage as char no-undo init ?.
        def var lErrorNum as int no-undo init ?.
        def var cReceivedToken as char no-undo.
        cReceivedToken = Jwt:builder():setExpiresInSeconds(1):signWithHS256Key("mySecretKey"):compact().
        
        // when
        _waitForSeconds(2).
        do on error undo, throw:
            Jwt:parseBuilder()
                :setSigningKeyHS256("mySecretKey")
                :parseClaimsJws(cReceivedToken).
            lParsedSuccessfully = true.
            catch e as JwtError:
                lErrorcaught = true.
                cErrorMessage = e:GetMessage(1).
                lErrorNum = e:GetMessageNum(1).            
            end catch.
        end.
        
        // then
        Assert:IsFalse(lParsedSuccessfully).
        Assert:isTrue(lErrorcaught).
        Assert:IsTrue(cErrorMessage > "").
        Assert:IsTrue(lErrorNum > 0).      
          
    end method.    
    
    method private void _waitForSeconds(piSeconds as int): 
        def var iDestinationTime as int no-undo.
        
        iDestinationTime = time + piSeconds.
        do while (iDestinationTime > time):
            // do nothing
        end.
        
    end method.  
end class.