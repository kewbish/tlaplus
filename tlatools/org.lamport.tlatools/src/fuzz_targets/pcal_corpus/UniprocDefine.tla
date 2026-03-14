---- MODULE UniprocDefine ----
(*
--algorithm UniprocDefine
  variables n = 0 ;
  define nplus1 == n + 1
         nplus2 == nplus1 + 1
  end define ;
  procedure Foo(a)
    variable b = 2 ;
    begin foo : n := nplus2 + a + b ;
                return ;
    end procedure ; 
  begin  main : call Foo(2) ;
         minor: assert n = 6 ;
  end algorithm
*)
====
