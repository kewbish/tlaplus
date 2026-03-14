---- MODULE MPFactorial ----
(*
--algorithm Factorial
  variable result = [i \in 1..3 |-> 1];        \* are comments ok?
  procedure FactProc(arg1 (* = 0 *) )    (* are comments ok? *)
   (* what about (* nested multi-line *)
       comments? *)
    variable u = 1 ;
    begin p1 : if arg1 = 0
                 then return;     \* HERE IS A 
                 else result[self] := result[self] * arg1;
                      call FactProc ( arg1 - 1) ;
                      return;
               end if;
    end procedure
  process Main \in 1..2 
    begin
    a1 : call FactProc( 5 ) ;
    a2 : assert result[self] = 120 ;
  end process
  process Minor = 3
    begin
    b1 : call FactProc( 5 ) ;
    b2 : assert result[3] = 120 ;
  end process
  end algorithm
**************************************************************************
*)
====
