---- MODULE MergeSort ----
(*
--algorithm Mergesort
  variables a \in UNION {[1..N -> 1..N] : N \in 0..ArrayLen} ;
            b = [x \in DOMAIN a |-> 99]  \* ;
  procedure mergesort(l, r)
    variables i ; j  ; k ; m \* ; 
    begin l1: if r - l > 0
                then      m := (r + l) \div 2 ;
                     l2 : call mergesort(l, m) ;
                     l3 : call mergesort(m+1, r) ;
                     l4 : i := m ;
                     l5 : while i \geq l
                            do b[i] := a[i];
                               i := i - 1 \* ;
                          end while ;
                          (*************************************************)
                          (* I don't know what the Pascal statement        *)
                          (*                                               *)
                          (*       for i := m downto l ...                 *)
                          (*                                               *)
                          (* is supposed to set i to if m < l, so the      *)
                          (* algorithm reports an error and stops in this    *)
                          (*************************************************)
                          if m \geq l
                            then i := l ; 
                            else print "not sure of semantics of Pascal" ;
                                 i := CHOOSE x \in {} : FALSE ;
                          end if ;
                          j := m + 1 ;
                     l6 : while j \leq r
                            do b[r + m + 1 - j] := a[j] ;
                               j := j + 1 ;
                          end while ;
                          (*************************************************)
                          (* I don't know what the Pascal statement        *)
                          (*                                               *)
                          (*       for j := m+1 to r ...                   *)
                          (*                                               *)
                          (* is supposed to set j to if m+1 < r, so the    *)
                          (* algorithm reports an error and stops in this    *)
                          (*************************************************)
                          if m+1 \leq r
                            then j := r ;  
                            else print "not sure of semantics of Pascal" ;
                                 i := CHOOSE x \in {} : FALSE ;
                          end if ;
                          k := l ;
                     l7 : while k \leq r
                            do if b[i] < b[j]
                                 then a[k] := b[i] ;
                                      i := i + 1 ;
                                 else a[k] := b[j] ;
                                      j := j - 1 ;
                               end if ;
                            k := k + 1 ;
                          end while ;
              end if ;
          l8: return ;
    end procedure
  begin  main : call mergesort (1, Len(a)) ;
  end algorithm
*)
====
