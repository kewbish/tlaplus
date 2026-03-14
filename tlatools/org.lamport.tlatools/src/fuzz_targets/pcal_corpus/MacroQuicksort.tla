---- MODULE MacroQuicksort ----
(*
--algorithm Quicksort
  variables Ainit \in [1..ArrayLen -> 1..ArrayLen]; A = Ainit;
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
  procedure  QS(qlo = 1, qhi = 1)
    variable pivot = 1 ;
    begin qs1 : if qlo < qhi
                  then       Partition(pivot, qlo, qhi) ;
                       qs2 : call QS(qlo, pivot) ;
                       qs3 : call QS(pivot +1,qhi) ;
                end if;
          qs4 : return ;
    end procedure
  begin  main : call QS(1, Len(A)) ;
         test : assert     A \in PermsOf(Ainit)
                       /\ \A i, j \in 1..ArrayLen : 
                            (i < j) =>  A[i] \leq A[j]
  end algorithm
*)
====
