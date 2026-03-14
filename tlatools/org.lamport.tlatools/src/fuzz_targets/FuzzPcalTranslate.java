package fuzz_targets;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.Arrays;

import pcal.Translator;
import pcal.ValidationCallBack;
import util.ToolIO;

public class FuzzPcalTranslate {
    private static final String[] ARGS = {"-nocfg", "-unixEOL", "FuzzPcal.tla"};
    private static final ValidationCallBack CALLBACK = new ValidationCallBack.Noop();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String payload = data.consumeString(8192);
        if (payload == null || payload.isEmpty()) {
            return;
        }

        final String moduleName = "FuzzPcal";
        final boolean useCSyntax = data.consumeBoolean();
        final boolean fair = data.consumeBoolean();

        final String source = buildWrappedModule(moduleName, payload, useCSyntax, fair);

        try {
            final Translator translator = new Translator(source, ARGS);
            final boolean translated = translator.translate(CALLBACK);
            if (!translated) {
                final String[] messages = ToolIO.getAllMessages();
                if (!hasExpectedTranslationError(messages)) {
                    throw new IllegalStateException(
                            "PlusCal translation failed without a recognized parse/translation error: "
                                    + Arrays.toString(messages));
                }
            }
            translator.getMapping();
            translator.getOutput();
        } catch (RuntimeException | Error unexpected) {
            throw unexpected;
        }
    }

    private static boolean hasExpectedTranslationError(final String[] messages) {
        if (messages == null || messages.length == 0) {
            return false;
        }
        for (String message : messages) {
            if (message == null) {
                continue;
            }
            final String m = message.toLowerCase();
            if (m.contains("unrecoverable error")
                    || m.contains("parsealgorithmexception")
                    || m.contains("missing `")
                    || m.contains("unknown error at or before")
                    || m.contains("assignment to undeclared variable")
                    || m.contains("duplicate labeling")
                    || m.contains("missing body")) {
                return true;
            }
        }
        return false;
    }

    private static String buildWrappedModule(
            final String moduleName,
            final String payload,
            final boolean useCSyntax,
            final boolean fair) {
        final StringBuilder sb = new StringBuilder();
        sb.append("---- MODULE ").append(moduleName).append(" ----\n");
        sb.append("(*\n");
        if (useCSyntax) {
            sb.append(fair ? "--fair algorithm FuzzAlg {\n" : "--algorithm FuzzAlg {\n");
            sb.append(payload).append("\n");
            sb.append("}\n");
        } else {
            sb.append(fair ? "--fair algorithm FuzzAlg\n" : "--algorithm FuzzAlg\n");
            sb.append("begin\n");
            sb.append(payload).append("\n");
            sb.append("end algorithm;\n");
        }
        sb.append("*)\n");
        sb.append("====\n");
        return sb.toString();
    }
}
