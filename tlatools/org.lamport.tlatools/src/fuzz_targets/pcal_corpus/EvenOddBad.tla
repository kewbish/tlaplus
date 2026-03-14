---- MODULE EvenOddBad ----
(*
--algorithm EvenOddBad
variable result \in { TRUE, FALSE };
procedure Even (xEven = 0)
begin
  Even1: if xEven = 0 then result := TRUE;
         else call Odd(xEven - 1);
         end if;
     e1  :  return;
  end procedure;
procedure Odd (xOdd = 0)
begin
  Odd1: if xOdd = 0 then result := FALSE;
        else call Even(xOdd - 1);
        end if;
      o1 :  return;
  end procedure
begin
  a1: call Even(2);
  a2: print result;
end algorithm
*)
====
