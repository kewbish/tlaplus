---- MODULE RAB ----
(*
--algorithm rab

    variables
        (****************************************************************)
        (* Global variable containing flags for all attributes.   The   *)
        (* initial state has all valid and value bits as FALSE.         *)
        (****************************************************************)
        flags = [ a \in Attr |-> [ valid |-> FALSE, value |-> FALSE ]];


        (****************************************************************)
        (* Oracle that says what the value is for each attribute.       *)
        (* Technically this is a variable, but we never change it.      *)
        (****************************************************************)
        calc \in [ Attr -> { FALSE, TRUE } ];




    process work \in Pid
        variables
            (************************************************************)
            (* Arbitrary initial values of the correct type.            *)
            (************************************************************)
            temp = CHOOSE f \in Flags : TRUE;
            myattr = CHOOSE a \in Attr : TRUE;
    begin
      Loop:
        while TRUE do
            (************************************************************)
            (* Choose an attribute to access.                           *)
            (************************************************************)
            with attr \in Attr do myattr := attr; end with;

            if \lnot flags[myattr].valid then
                (********************************************************)
                (* My component of the global flags variable is not     *)
                (* valid.   Compute the temporary.                      *)
                (********************************************************)
                temp :=
                [ a \in Attr |->
                    IF a = myattr
                    THEN [ valid |-> TRUE, value |-> calc[myattr] ]
                    ELSE [ valid |-> FALSE, value |-> FALSE ]
                ];

              FetchFlags:
                (********************************************************)
                (* Fetch the global flags variable and "bitwise or" it  *)
                (* into the temporary.                                  *)
                (********************************************************)
                temp := flags | temp;

              StoreFlags:
                (********************************************************)
                (* Store the temporary back into the global flags       *)
                (* variable.                                            *)
                (********************************************************)
    
                flags := temp;
            end if;

          ReadFlags:
            (************************************************************)
            (* Read my component of the global flags variable.  It is   *)
            (* supposed to be consistent with the oracle.               *)
            (************************************************************)
            \* assert flags[myattr].value = calc[myattr];
            skip;
        end while;
    end process;
end algorithm
*)
====
