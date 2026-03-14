---- MODULE MultiprocDefine ----
(*
--algorithm MultiprocDefine
  variables n = 0 ;
  define nplus1 == n + 1 
         nplus2 == nplus1 + 1
  end define ;
  process Proc \in {1, 2, 3}
  variables i ;
  begin  main : i := nplus2 ;
                assert i = 2 ;
  end process
  end algorithm
*)
====
