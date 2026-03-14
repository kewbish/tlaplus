---- MODULE MPFactorial2 ----
(*
--algorithm Factorial
  variable result = [i \in 1..3 |-> 1];        
  procedure FactProc(arg1 = 0 )    
    variable u = 1 ;
    begin p1 : if arg1 = 0
                 then return;     
                 else result[self] := result[self] * arg1;
                      call FactProc2 ( arg1 - 1 ) ;
                      b: return;
               end if;
    end procedure
  procedure FactProc2(arg2 = 0)    
    variable u2 = 1 ;
    begin p12 : if arg2 = 0
                 then return;     
                 else result[self] := result[self] * arg2;
                      call FactProc ( arg2 - 1 ) ;
                      return;
               end if;
    end procedure
  process Main \in 1..2
  begin
    a1 : call FactProc( 5 ) ;
    a2 : assert result[self] = 120  
  end process
  process Minor = 3
  begin
    b1 : call FactProc( 5 ) ;
    b2 : assert result[3] = 120 
  end process
  end algorithm
**************************************************************************
*)
====
