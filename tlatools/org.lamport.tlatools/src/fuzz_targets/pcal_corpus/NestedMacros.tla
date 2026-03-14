---- MODULE NestedMacros ----
(*
--algorithm Test {
  variables x, y ;

  macro ff(a, b) {
    a := b
  }
  macro foo(a) {
   ff(z,a);
   y := a
  }

  macro bar(b) {
   x := b;
   foo(22)
  }
  process (foob  \in {1,2}) 
   variable z ;
  { l1 : z := 0 ; 
    l2 : bar(42);
          assert z = 22 /\ x = 42
  }
}
 **************************************************************************
*)
====
