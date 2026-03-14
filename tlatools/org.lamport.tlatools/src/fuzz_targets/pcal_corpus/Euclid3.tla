---- MODULE Euclid3 ----
(*
--algorithm EuclidAlg
variables u = 24 ; v \in 1 .. N ; v_ini = v ;
begin
lp: while u # 0 do   
        if u < v then u := v || v := u ;   
        end if ; 
     a: u := u - v; 
    end while ; 
    print <<v, "= GCD of 24 and ", v_ini>> ;
end algorithm
*)
====
