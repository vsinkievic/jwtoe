 
 /*------------------------------------------------------------------------
    File        : JwtBuilderTest
    Purpose     : 
    Syntax      : 
    Description : 
    Author(s)   : vsink_000
    Created     : Mon May 10 14:49:00 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using jwtoe.Jwt from propath.
using jwtoe.JwtBuilder from propath.
using OpenEdge.Core.Assert from propath.

block-level on error undo, throw.

class jwtoe.JwtBuilderTest:
    
    @Test.
    method public void testToken ():
        // given
        def var cToken as char no-undo.
        
        // when
        cToken = Jwt:builder()
            :setAudience("audience")
            :setIssuer("issuer")
            :setSubject("subject")
            :setClaim("key", "value")
            :signWithHS256Key("mySecretKey")
            :compact().
        
        // then
        Assert:Equals("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJrZXkiOiJ2YWx1ZSJ9.z7c2hq34UKmLFGt5hF5vRvjii380qiUD8eHwv92XnFI", cToken).
        
    end method.
      
end class.