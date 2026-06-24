// Export address-linked decompiler context; target bytes are never executed.
// @category Capathy
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class ExportEvidence extends HeadlessScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("output, hash, limit required");
        int limit = Integer.parseInt(args[2]);
        JsonObject report = new JsonObject();
        report.addProperty("schema", 1);
        report.addProperty("kind", "capathy.decompilation");
        report.addProperty("sha256", args[1]);
        report.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        if (analysisTimeoutOccurred()) {
            report.add("functions", new JsonArray());
            Files.writeString(Path.of(args[0]), new Gson().toJson(report), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            return;
        }
        JsonArray functions = new JsonArray();
        report.add("functions", functions);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception("cannot open program");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (iterator.hasNext() && count < limit && !monitor.isCancelled()) {
                Function function = iterator.next();
                if (function.isExternal()) continue;
                DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
                JsonObject entry = new JsonObject();
                entry.addProperty("address", function.getEntryPoint().toString());
                entry.addProperty("name", function.getName());
                String code = result.decompileCompleted() ? result.getDecompiledFunction().getC() : "";
                entry.addProperty("pseudocode", code.length() > 200000 ? code.substring(0, 200000) : code);
                entry.addProperty("complete", result.decompileCompleted() && code.length() <= 200000);
                JsonArray calls = new JsonArray();
                for (Function called : function.getCalledFunctions(monitor)) {
                    if (calls.size() >= 10000) break;
                    calls.add(called.getEntryPoint().toString());
                }
                entry.add("calls", calls);
                functions.add(entry);
                count++;
            }
            report.addProperty("truncated", iterator.hasNext());
            String json = new Gson().toJson(report);
            if (json.length() > 32 * 1024 * 1024) throw new Exception("report too large");
            Files.writeString(Path.of(args[0]), json, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        } finally { decompiler.dispose(); }
    }
}
