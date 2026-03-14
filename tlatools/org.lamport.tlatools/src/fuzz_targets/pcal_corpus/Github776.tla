---- MODULE Github776 ----
(*
--algorithm Playground {

    \* PlusCal does not have return values, but we can fake them
    variables
        retval,
        output

    procedure add(x, y) {
        do_add:
            retval := x + y;
            return;
    }

    procedure to_string(int) {
        do_to_string:
            assert int = 10; \* this model only needs to be able to convert one value to a string
            retval := "10";
            return;
    }

    fair process (main = 1) {
        step1: call add(3, 7);
        step2: call to_string(retval);
        step3: output := retval;
        step4: assert output = "10";
    }

}
*)
====
