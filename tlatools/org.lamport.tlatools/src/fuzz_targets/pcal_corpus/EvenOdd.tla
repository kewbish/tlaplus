---- MODULE EvenOdd ----
(*
--algorithm EvenOdd
variable result = FALSE;
procedure Even (xEven = 0)
begin
  Even1: if xEven = 0 then
           result := TRUE;
           return;
         else
           call Odd(xEven - 1);
           return;
         end if;
  end procedure
procedure Odd (xOdd = 0)
begin
  Odd1: if xOdd = 0 then result := FALSE;
        else call Even(xOdd - 1);
        end if;
  Odd2: return;
  end procedure
begin
  a1: call Even(N);
  a2: print result;
end algorithm
*)
====
