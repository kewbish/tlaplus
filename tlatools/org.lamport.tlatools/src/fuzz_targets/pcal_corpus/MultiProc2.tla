---- MODULE MultiProc2 ----
(*
--algorithm MultiProc2
    variables
      x = [i \in ProcSet |-> CASE i = 41 -> 1 []
                                 i = 42 -> 2 []
                                 i = 43 -> 3];
      sum = 0 ;
      done = {};
    procedure Sum(arg = 0)
      variable u = 1 ;
      begin p1 : u := u + arg ;
            p2 : sum := sum + u;
                 return;
      end procedure
    process ProcA = 41
      variable y = 0  ;
      begin a1 : call Sum( x [ 41 ] + y ) ;
            a2 : done := done \cup { 41 } ;
            a3 : when done = { 41, 42, 43 } ;
                 when Print ( sum , TRUE ) ;
      end process
    process ProcB \in {42, 43}
      variable z \in {2, 3} ;
      begin b1 : call Sum ( x [ self ] + z ) ;
            b2 : done := done \cup { self } ;
      end process
    end algorithm
*)
====
