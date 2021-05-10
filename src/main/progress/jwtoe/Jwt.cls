 
 /*------------------------------------------------------------------------
    File        : Jwt
    Purpose     : 
    Syntax      : 
    Description : JSON Wet Token builder for Progress OpenEdge
    Author(s)   : Valdemar Sinkievič
    Created     : Mon May 10 09:39:44 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.
using jwtoe.JwtBuilder from propath.
using jwtoe.JwtParser from propath.

block-level on error undo, throw.

class jwtoe.Jwt: 
    
    method static public JwtBuilder builder ():
        return new JwtBuilder().
    end method.
    
    method static public JwtParser parseBuilder():
        return new JwtParser().
    end method.

end class.