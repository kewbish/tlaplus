---- MODULE InnerLabeledIf ----
(*
--algorithm InnerLabeledIf
    variable x \in 1..4 ;
    begin a : if (x < 3)
                then if (x = 1)
                       then skip ; 
                            b : assert x = 1 
                       else c : assert x = 2
                     end if ;
                else if (x = 3)
                       then skip ; 
                            d : assert x = 3 
                       else e : assert x = 4 ;
                     end if ;
              end if ;
          f : print("made it to end") ;
    end algorithm
*)
====
