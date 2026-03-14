---- MODULE Factorial ----
(*
--algorithm Factorial
  variable result = 1;        \* are comments ok?
  procedure FactProc(arg1 = 0)    (* are comments ok? *)
   (* what about (* nested multi-line *)
       comments? *)
    variable u = 1 ;
    begin p1 : if arg1 = 0
                 then return;     \* HERE IS A 
                 else result := result * arg1;
                      call FactProc ( arg1 - 1 ) ;
                      return;
               end if;
    end procedure
  begin
    a1 : call FactProc( 5 ) ;
    a2 : assert result = 120 ;
  end algorithm
**************************************************************************
*)
====
