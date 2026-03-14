---- MODULE TestReplace ----
(*
--algorithm TestReplace
macro IncrementX(u)
  begin X := X + u 
  end macro

procedure Bar(u, v)
 begin a: assert u = v;
          return;
 end procedure

procedure Foo1(u, v)
 variable X = 0; Y = X ;
 begin
 a : assert Y = X ;
 b : while Y = X do 
         Y := Y - 1;
     end while ;
     assert Y = X - 1;
     with id = X do assert id = 0  end with ;
     if X = 0
       then  c: call Bar(X, 0)
       else  assert FALSE 
     end if ;
 d : print <<X, " = 0">> ;
     IncrementX(X+1) ;
     assert X = 1 ;
 e:  return 
end procedure

procedure Foo2(u, v)
 variable X = 9; Z = X ;
 begin
 a : assert Z = X ;
 b : while Z = X do 
         Z := Z - 1;
     end while ;
     assert Z = X - 1;
     with id = X do assert id = 9  end with ;
     if X = 9
       then  c: call Bar(X, 9)
        
       else  assert FALSE 
     end if ;
 d : print <<X, " = 9">> ;
     IncrementX(X+1) ;
     assert X = 19 ;
 e:    return 
end procedure

begin
start : call Foo1(1, 2) ;
b : call Foo2(1, 2) ;
end algorithm

**********************
*)
====
