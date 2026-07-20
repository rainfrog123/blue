using System;
using System.Diagnostics;
using System.IO;
using System.Text;

class Shim
{
    static int Main(string[] args)
    {
        string here = AppDomain.CurrentDomain.BaseDirectory;
        string overrideFile = Environment.GetEnvironmentVariable("OCTO_HID_OVERRIDE_FILE");
        if (string.IsNullOrEmpty(overrideFile))
        {
            // Prefer override sitting next to this shim (app-dir spoof layout)
            overrideFile = Path.Combine(here, "hid_override.txt");
            if (!File.Exists(overrideFile))
                overrideFile = Path.GetFullPath(Path.Combine(here, "..", "hid_override.txt"));
        }

        string joined = string.Join(" ", args);
        bool wantsUuid =
            IndexOfCI(joined, "Win32_ComputerSystemProduct") >= 0
            || (IndexOfCI(joined, "csproduct") >= 0 && IndexOfCI(joined, "uuid") >= 0);

        if (wantsUuid && File.Exists(overrideFile))
        {
            Console.WriteLine(File.ReadAllText(overrideFile).Trim());
            return 0;
        }

        string realPs = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

        var psi = new ProcessStartInfo();
        psi.FileName = realPs;
        psi.Arguments = QuoteArgs(args);
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;

        using (var p = Process.Start(psi))
        {
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Console.Out.Write(stdout);
            Console.Error.Write(stderr);
            return p.ExitCode;
        }
    }

    static int IndexOfCI(string hay, string needle)
    {
        return hay.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
    }

    static string QuoteArgs(string[] args)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < args.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            string a = args[i];
            if (a.Length == 0) { sb.Append("\"\""); continue; }
            bool need = a.IndexOfAny(new char[] { ' ', '\t', '"', '&', '|', '<', '>', '^' }) >= 0
                        || a.IndexOf('(') >= 0 || a.IndexOf(')') >= 0;
            if (!need) { sb.Append(a); continue; }
            sb.Append('"');
            sb.Append(a.Replace("\"", "\\\""));
            sb.Append('"');
        }
        return sb.ToString();
    }
}
