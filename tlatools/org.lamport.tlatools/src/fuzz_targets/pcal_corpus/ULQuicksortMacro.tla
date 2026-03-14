---- MODULE ULQuicksortMacro ----
(*
--algorithm QuicksortMacro
  variables A \in [1..ArrayLen -> 1..ArrayLen];
            returnVal = 1;
  macro Partition(lo, hi)
    begin      with piv \in lo..(hi-1)
                  do returnVal := piv ;
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
    begin (*qs1 :*) if qlo < qhi
                  then       Partition(qlo, qhi) ;
                       (*qs2 :*) pivot := returnVal ;
                       (*qs3 :*) call QS(qlo, pivot) ;
                       (*qs4 :*) call QS(pivot +1,qhi) ;
                             return ;
                  else    return;
                end if;
    end procedure
  begin  (*main :*) call QS(1, Len(A)) ;
  end algorithm
*)
====
