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

public class FuzzSanyParse {
    private static final String TEMPLATE_PATH = "src/fuzz_targets/test_spec.tla";
    private static final String LOCAL_PATH = "test_spec.tla";
    private static final String MODULE_HEADER = "MODULE Test";

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String moduleName = new String(new char[] {
                data.consumeCharNoSurrogates(),
                data.consumeCharNoSurrogates(),
                data.consumeCharNoSurrogates(),
                data.consumeCharNoSurrogates()
        });

        final Path template = Files.exists(Path.of(TEMPLATE_PATH)) ? Path.of(TEMPLATE_PATH) : Path.of(LOCAL_PATH);
        try {
            final String source = Files.readString(template, StandardCharsets.UTF_8);
            final int moduleIdx = source.indexOf(MODULE_HEADER);
            if (moduleIdx < 0) {
                throw new IllegalStateException("Expected module header not found in " + template);
            }

            final String mutatedSource = source.substring(0, moduleIdx)
                    + "MODULE " + moduleName
                    + source.substring(moduleIdx + MODULE_HEADER.length());

            final Path mutatedSpec = Files.createTempFile("test_spec_", ".tla");
            try {
                Files.writeString(mutatedSpec, mutatedSource, StandardCharsets.UTF_8);
                final SpecObj spec = new SpecObj(mutatedSpec.toString(), null);
                try (PrintStream sink = new PrintStream(OutputStream.nullOutputStream())) {
                    SANY.frontEndParse(spec, sink);
                } catch (ParseException expected) {
                    // Parse errors are OK
                }
            } finally {
                Files.deleteIfExists(mutatedSpec);
            }
        } catch (RuntimeException | Error unexpected) {
            throw unexpected;
        } catch (IOException unexpected) {
            throw new RuntimeException(unexpected);
        }
    }
}
