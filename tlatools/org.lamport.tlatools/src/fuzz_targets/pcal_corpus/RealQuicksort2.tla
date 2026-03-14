---- MODULE RealQuicksort2 ----
(*
--algorithm RealQuicksort2
  variables A \in UNION {[1..N -> 1..N] : N \in 0..MaxLen};
            Uns = {1..Len(A)} ;
            new = {} ;
            next = {} ;
  procedure Part(parg)
    begin pt1 : with new1 \in
                      {Min(parg)..piv : piv \in parg \ {Max(parg)}}  do
                with new2 = parg \ new1      do
                new := {new1, new2} ;
                with Ap \in
                      {AA \in PermsOf(A) :
                             (\A i \in 1..Len(A) \ parg : AA[i] = A[i])
                          /\ (\A i \in new1, j \in new2 :
                                  AA[i] \leq AA[j])}  do
                A := Ap;
                return ;
                end with ;
                end with ;
                end with;
    end procedure;
  begin rqs : while Uns # {}
               do with nxt \in Uns do next := nxt ;
                  end with ;
                  Uns := Uns \ {next};
                  if Cardinality(next) > 1
                    then        call Part(next) ;
                         rqs2 : Uns := Uns \cup new ;
                  end if ;
              end while;
  end algorithm
*)
====
