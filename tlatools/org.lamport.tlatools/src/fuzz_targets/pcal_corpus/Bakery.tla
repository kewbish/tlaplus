---- MODULE Bakery ----
(*
--algorithm Bakery
  variable num = [i \in Proc |-> 0] ;
           choosing = [i \in Proc |-> FALSE];
  process proc \in Proc
    variables read = { }; max = 0 ; nxt = self ;
    begin loop : while TRUE
                   do      choosing[self] := TRUE;
                           read := { self };
                           max  := 0 ;
                      d1 : while read # Proc
                            do  with p \in Proc \ read
                                  do if num[p] > max
                                       then max := num[p];
                                     end if ;
                                     read := read \cup {p};
                                end with ;
                            end while ;
                      d2 : num[self] := max + 1 ;
                      d3 : choosing[self] := FALSE ;
                           read := { self } ;
                      w1 : while read # Proc
                            do  with p \in Proc \ read
                                  do     when ~ choosing[p] ;
                                         nxt := p ;
                                end with;
                            w2: when \/ num[nxt] = 0 
                                     \/ num[nxt] > num[self]
                                     \/ /\ num[nxt] = num[self]
                                        /\ nxt > self   ;
                                read := read \cup { nxt } ;
                           end while;
                     cs  : when TRUE ;
                    exit : num[self] := 0;
                  end while;
    end process
  end algorithm
*)
====
