package fuzz_targets;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.OutputStream;
import java.io.PrintStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import tla2sany.modanalyzer.SpecObj;
import tla2sany.drivers.SANY;
import tla2sany.parser.ParseException;

public class FuzzSanyParse_1 {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String source = data.consumeRemainingAsString();

        if (source == null || source.isEmpty()) {
            return;
        }

        Path tempSpec = null;
        try {
            tempSpec = Files.createTempFile("jazzer_sany_", ".tla");
            Files.writeString(tempSpec, source, StandardCharsets.UTF_8);

            final SpecObj spec = new SpecObj(tempSpec.toString(), null);

            try (PrintStream sink = new PrintStream(OutputStream.nullOutputStream())) {
                SANY.frontEndParse(spec, sink);
            } catch (ParseException expected) {
                // Syntax errors are expected during fuzzing.
            }
        } catch (RuntimeException | Error unexpected) {
            throw unexpected;
        } catch (IOException unexpected) {
            throw new RuntimeException(unexpected);
        } finally {
            if (tempSpec != null) {
                try {
                    Files.deleteIfExists(tempSpec);
                } catch (IOException ignored) {
                    // Ignore cleanup failure.
                }
            }
        }
    }
}