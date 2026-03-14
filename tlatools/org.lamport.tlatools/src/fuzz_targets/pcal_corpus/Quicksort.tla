---- MODULE Quicksort ----
(*
--algorithm Quicksort
  variables Ainit \in [1..ArrayLen -> 1..ArrayLen]; A = Ainit;
            returnVal = 1
  procedure Partition(lo, hi )
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
  procedure  QS(qlo, qhi )
    variable pivot ;
    begin qs1 : if qlo < qhi
                  then       call Partition(qlo, qhi) ;
                       qs2 : pivot := returnVal ;
                       qs3 : call QS(qlo, pivot) ;
                       qs4 : call QS(pivot +1,qhi) ;
                             return ;
                  else    return;
                end if;
    end procedure
  begin  main : call QS(1, Len(A)) ;
         test : assert     A \in PermsOf(Ainit)
                       /\ \A i, j \in 1..ArrayLen : 
                            (i < j) =>  A[i] \leq A[j]
  end algorithm
*)
====
