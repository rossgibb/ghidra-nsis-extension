package nsis.tests;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.headless.HeadlessAnalyzer;

public class AnalyzerHelper {

  public static void main(String[] args) throws IOException {
    List<File> filesToImport = new ArrayList<File>();
    filesToImport
        .add(new File("/usr/local/google/home/rossgibb/dev/hello_world/import/nsis_with_lzma.exe"));
    Path myTempDir = Files.createTempDirectory("ghidra_test");
    HeadlessAnalyzer analyzer = HeadlessAnalyzer.getInstance();
    analyzer.processLocal(myTempDir.toString(), "headless_test",
        "/usr/local/google/home/rossgibb/dev/hello_world/import", filesToImport);
  }
}
