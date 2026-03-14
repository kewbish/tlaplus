---- MODULE CCallReturn1 ----
(*
--algorithm CallReturn1 {
    procedure Proc1(arg1 = 0) 
      variable u = 1 ;
          { p1 : u := 2 ;
                 call Proc2 ( 2 * u ) ;
            p2 : assert u = 2;
                 assert arg1  = 4  ;
                 call Proc2 ( 2 * u + 1 ) ;
                 return ; }

    procedure Proc2(arg2 = 0) 
      variable v = 42 ;
          { q1 : assert v = 42;
                 assert arg2 \in {4, 5} ;
                 call Proc3 ( v + arg2 ) ;
                 return }

    procedure Proc3(arg3 = 0)
          { r1 : assert arg3 \in {46, 47} ;
                 return ; } ;

    {
      a1 : call Proc1( 4 ) ;
    } }
*)
====
