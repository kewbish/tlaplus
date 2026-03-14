---- MODULE MacroRealQuicksort ----
(*
--algorithm Quicksort
  variables Ainit \in [1..N -> 1..N]; A = Ainit;
            S = {<<1,N>>} ; pivot = 1 ;
  macro Partition(pivot, lo, hi)
    begin   with piv \in lo..(hi-1)
              do pivot := piv ;
                 with Ap \in
                      {AA \in PermsOf(A) :
                             (\A i \in 1..(lo-1) : AA[i] = A[i])
                          /\ (\A i \in (hi+1)..Len(A) : AA[i] = A[i])
                          /\ (\A i \in lo..piv, j \in (piv+1)..hi :
                                  AA[i] \leq AA[j])}
                   do A := Ap;
                   end with ;
              end with;
    end macro
   begin qs1 : while S # {}
                do with I \in S
                   do if I[1] < I[2]
                        then Partition(pivot, I[1], I[2]) ;
                             S := (S \ {I}) 
                                    \cup {<<I[1], pivot>>, <<pivot+1, I[2]>>}
                        else S := (S \ {I}) 
                    end if
                   end with
                end while
  end algorithm
*)
====
