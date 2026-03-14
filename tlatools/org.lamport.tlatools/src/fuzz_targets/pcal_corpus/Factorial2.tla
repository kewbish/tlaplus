---- MODULE Factorial2 ----
(*
--algorithm Factorial
  variable result = 1;        
  procedure FactProc(arg1 = 0 )    
    variable u = 1 ;
    begin p1 : if arg1 = 0
                 then return;     
                 else result := result * arg1;
                      call FactProc2 ( arg1 - 1 ) ;
                      b: return;
               end if;
    end procedure
  procedure FactProc2(arg2 = 0)    
    variable u2 = 1 ;
    begin p12 : if arg2 = 0
                 then return;     
                 else result := result * arg2;
                      call FactProc ( arg2 - 1 ) ;
                      return;
               end if;
    end procedure
  begin
    a1 : call FactProc( 5 ) ;
    a2 : if result = 120  then print <<"Correct =", 120>>;
                          else print <<"Error = ", result>> ;
         end if;
  end algorithm
**************************************************************************
*)
====
