---- MODULE Quicksort2Procs ----
(*
--algorithm Quicksort
  variables A \in [1..ArrayLen -> 1..ArrayLen];
            returnVal = 99;
  procedure Partition(lo = 99, hi = 99)
    begin pt1 : with piv \in lo..(hi-1)
                  do returnVal := piv ;
                     with Ap \in
                      {AA \in PermsOf(A) :
                             (\A i \in 1..(lo-1) : AA[i] = A[i])
                          /\ (\A i \in (hi+1)..Len(A) : AA[i] = A[i])
                          /\ (\A i \in lo..piv, j \in (piv+1)..hi :
                                  AA[i] \leq AA[j])}
                        do A := Ap;
                        return ;
                     end with ;
                end with;
    end procedure
  procedure  QS(qlo = 99, qhi = 99)
    variable pivot = 99 ;
    begin qs1 : if qlo < qhi
                  then       call Partition(qlo, qhi) ;
                       qs2 : pivot := returnVal ;
                       qs3 : call QS2(qlo, pivot) ;
                       qs4 : call QS2(pivot +1,qhi) ;
                             return ;
                  else    return;
                end if;
    end procedure
  procedure  QS2(qlo2 = 99, qhi2 = 99)
    variable pivot2 = 99 ;
    begin 2qs1 : if qlo2 < qhi2
                  then       call Partition(qlo2, qhi2) ;
                       2qs2 : pivot2 := returnVal ;
                       2qs3 : call QS(qlo2, pivot2) ;
                       2qs4 : call QS(pivot2 +1,qhi2) ;
                             return ;
                  else    return;
                end if;
    end procedure
  begin  main : call QS(1, Len(A)) ;
  end algorithm
*)
====
