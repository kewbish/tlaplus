---- MODULE Either5 ----
(*
--algorithm Either
      variables x = 0 ; y = 0 ; z = 0 ;
      procedure Foo(a) 
       begin c: x := x + a ;
                return 
       end procedure;           
      begin a: either x := 1 ; y := 0 ;
                   or y := 1 ; 
                   or call Foo(1) ; 
                     b: assert x = 1 ;
               end either ;
             d:  assert x+y = 1 ;
     end algorithm
*)
====
