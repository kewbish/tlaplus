package fuzz_targets;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import tlc2.TLC;
import util.ToolIO;

public class FuzzTLCSimulate {
    private static final int MAX_SOURCE_CHARS = 32768;

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String source = data.consumeString(MAX_SOURCE_CHARS);
        if (source == null || source.isEmpty()) {
            return;
        }

        Path tempSpec = null;
        try {
            tempSpec = Files.createTempFile("jazzer_tlc_", ".tla");
            Files.writeString(tempSpec, source, StandardCharsets.UTF_8);

            // Capture TLC output and avoid writing to stdout/stderr during fuzzing.
            ToolIO.setMode(ToolIO.TOOL);
            ToolIO.reset();

            final TLC tlc = new TLC();
            final String specPath = tempSpec.toString();
            final String[] args = {
                "-simulate", "num=1",
                "-depth", "3",
                "-workers", "1",
                "-cleanup",
                "-config", specPath,
                specPath
            };

            if (!tlc.handleParameters(args)) {
                return;
            }

            tlc.process();
        } catch (RuntimeException expected) {
            if (!isExpectedRuntimeFailure(expected)) {
                throw expected;
            }
        } catch (Error unexpected) {
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

    private static boolean isExpectedRuntimeFailure(Throwable t) {
        Throwable cur = t;
        while (cur != null) {
            final String name = cur.getClass().getName();
            if (name.equals("tlc2.tool.ConfigFileException")
                    || name.equals("tla2sany.parser.ParseException")
                    || name.equals("tla2sany.semantic.AbortException")
                    || name.equals("tla2sany.semantic.SemanticException")
                    || name.startsWith("util.Assert$TLCRuntimeException")) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }
}
