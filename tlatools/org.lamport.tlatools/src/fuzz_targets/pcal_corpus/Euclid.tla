---- MODULE Euclid ----
(*
--algorithm Euclid
  variables u_ini \in 1 .. MaxNum ; 
            v_ini \in 1 .. MaxNum ;
            u = u_ini ; v = v_ini ;
  begin a : while u # 0
              do     if u < v then u := v || v := u ; end if ;
                 b:  u := u - v;
            end while ;
            assert v = GCD(u_ini, v_ini) ;
            \* print <<"gcd of ", u_ini, v_ini, " equals ", v >> ;
  end algorithm 

*)
                    
GCD(x, y) == CHOOSE i \in (1..x) \cap (1..y) :
                /\ x % i = 0 
                /\ y % i = 0
                /\ \A j \in (1..x) \cap (1..y) :
                        /\ x % j = 0 
                        /\ y % j = 0
                        => i \geq j
*)
====
