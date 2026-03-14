---- MODULE CallReturn1 ----
(*
--algorithm CallReturn1
    procedure Proc1(arg1)
      variable u ;
      begin p1 : u := 2 ;
                 call Proc2 ( 2 * u ) ;
            p2 : assert u = 2;
                 assert arg1  = 4  ;
                 call Proc2 ( 2 * u + 1 ) ;
                 return ;
      end procedure
    procedure Proc2(arg2 = 0)
      variable v = 42 ;
      begin q1 : assert v = 42;
                 assert arg2 \in {4, 5} ;
                 call Proc3 ( v + arg2 ) ;
                 return ;
      end procedure
    procedure Proc3(arg3 = 0)
      begin r1 : assert arg3 \in {46, 47} ;
                 return ;
      end procedure
    begin
      a1 : call Proc1( 4 ) ;
    end algorithm
****
*)
====
