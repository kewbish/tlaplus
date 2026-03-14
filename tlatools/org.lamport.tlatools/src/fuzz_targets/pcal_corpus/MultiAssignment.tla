---- MODULE MultiAssignment ----
(*
--algorithm MultiAssignment
  process Proc \in 1..3
  variables A = [i \in 1..5 |-> i] ; x = 0 ;
  begin a : A[1] := A[3] ||  x := 7 || A[3] := A[1] ;
            assert <<3 , 1>> = <<A[1], A[3]>> ;
        b : assert <<3 , 1>> = <<A[1], A[3]>> ;
  end process
  end algorithm 

***
*)
====
