---- MODULE Test ----
(*
--algorithm bug
variables x = 0 ; y = 0 ;
macro foo()
   begin if TRUE then if TRUE then y := 22 ;
                              else y := 42  end if
                 else  with a = 47 ; b = 77 ; do
                        y := 27
                       end with  end if
   end macro 
procedure Bar() 
  begin Q: skip ;
           foo() ;
           return 
  end procedure 
begin  L1 :   y := 1 ;
       L3 :   skip ;
              if x > 0 then foo() 
                       else x := 17 end if;
       L2 : assert x = 17 ;
            foo() ;
            assert y = 22 
end algorithm
*)
====
