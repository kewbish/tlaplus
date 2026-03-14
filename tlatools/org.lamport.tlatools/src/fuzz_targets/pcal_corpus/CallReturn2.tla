---- MODULE CallReturn2 ----
(*
--algorithm Test
   variable depth = 3
   procedure P(a = 7) 
      variable x = a ; y = x+1 ;
      begin P1: assert a = 1;
                assert x = a;
                assert y = a+1;
                return;
      end procedure 
  procedure Q() 
     begin Q1: call P(1) ;
              return ;
      end procedure 
  procedure PP(aa = 7)
      variable xx = aa ; yy = xx+1 ;
      begin PP1: if depth > 0
                  then assert aa = 1;
                     assert xx = aa;
                     assert yy = aa+1;
                     depth := depth - 1 ;
                     call PP(1) ;
                     return;
                  else return 
                end if 
      end procedure 
  procedure R(r = 0)
     variable x
     begin R1: x := 2 ;
           R2: call S(x) ;
               return 
     end procedure
  procedure S(s)
    begin S1: assert s = 2 ;
               return ;
    end procedure 
 begin A: call P(1) ;
       B: call Q() ;
       C: call PP(1) ;
  end algorithm
*)
====
