 
 /*------------------------------------------------------------------------
    File        : JwtException
    Purpose     : 
    Syntax      : 
    Description : 
    Author(s)   : vsink_000
    Created     : Mon May 10 15:00:52 EEST 2021
    Notes       : 
  ----------------------------------------------------------------------*/

using Progress.Lang.*.

block-level on error undo, throw.

class jwtoe.JwtError inherits AppError final: 
        
    constructor public JwtError ( input pcReturnValue as character ):
        super (input pcReturnValue).
        
    end constructor.

        
    constructor public JwtError ( input pcErrorMessage as character, input piMessageNum as integer ):
        super (input pcErrorMessage, input piMessageNum).
        
    end constructor.

        
    constructor public JwtError (  ):
        super ().
        
    end constructor.
    
end class.