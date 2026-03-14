---- MODULE CBakery ----
(*
--algorithm Bakery {
  variable num = [i \in Proc |-> 0] ;
           choosing = [i \in Proc |-> FALSE];
  process (proc \in Proc) 
    variables read = { }; max = 0 ; nxt = self ;
    { loop : while (TRUE) {
              choosing[self] := TRUE;
              read := { self };
              max  := 0 ;
         d1 : while (read # Proc)
                with (p \in Proc \ read) {
                  if (num[p] > max) max := num[p];
                  read := read \cup {p} }  ;
         d2 : num[self] := max + 1 ;
         d3 : choosing[self] := FALSE ;
              read := { self } ;
         w1 : while (read # Proc) {
                with (p \in Proc \ read) {
                  when ~ choosing[p] ;
                  nxt := p } ; 
            w2: when \/ num[nxt] = 0 
                     \/ num[nxt] > num[self] 
                     \/ /\ num[nxt] = num[self] 
                        /\ nxt > self   ;
                read := read \cup { nxt } };
        cs  : when TRUE ;
              exit : num[self] := 0; } } }
*******
*)
====
