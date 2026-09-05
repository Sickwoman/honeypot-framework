using System.Text.Json;
using System.Text.RegularExpressions;

enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

record Finding(string Rule, Severity Severity, string File, int Line, string Message, string Evidence);

static class SecurityAudit
{
    private static readonly string[] Extensions = [".yml", ".yaml", ".conf", ".cfg", ".ini", ".json", ".py", ".tf", ".sh"];
    private static readonly string[] SkipDirectories = [".git", "node_modules", "dist", "bin", "obj", "__pycache__", ".pytest_cache"];
    private static readonly Regex SecretAssignment = new(
        @"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*(?:[""'][^""']{8,}[""']|[A-Za-z0-9+/=_-]{20,})",
        RegexOptions.Compiled);
    private static readonly Regex PlaceholderCredential = new(
        @"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[""']?(changeme|password|admin)[""']?",
        RegexOptions.Compiled);

    public static IReadOnlyList<Finding> Scan(string root)
    {
        var findings = new List<Finding>();
        foreach (var file in EnumerateFiles(root))
        {
            string[] lines;
            try { lines = File.ReadAllLines(file); }
            catch (IOException) { continue; }
            for (var index = 0; index < lines.Length; index++)
            {
                var line = lines[index];
                var lineNumber = index + 1;
                var isComment = line.TrimStart().StartsWith("#") || line.TrimStart().StartsWith("//");
                var hasDefault = !isComment && PlaceholderCredential.IsMatch(line)
                    && (Path.GetExtension(file).Equals(".py", StringComparison.OrdinalIgnoreCase)
                        ? line.Contains('"') || line.Contains('\'')
                        : true);
                if (hasDefault)
                {
                    findings.Add(CreateFinding("DEFAULT-CREDENTIAL", Severity.Critical, file, lineNumber,
                        "Default or placeholder credential detected.", line));
                }
                AddPattern(findings, file, lineNumber, line,
                    "TLS-VERIFICATION-DISABLED", Severity.High,
                    "TLS certificate verification is disabled.",
                    new Regex(@"(?i)(insecure_skip_verify\s*:\s*true|verify_certs\s*=\s*false|verify_ssl\s*=\s*false|ssl_verify\s*[:=]\s*false)", RegexOptions.Compiled));
                AddPattern(findings, file, lineNumber, line,
                    "WILDCARD-MANAGEMENT-BIND", Severity.High,
                    "A management service binds to every network interface.",
                    new Regex(@"(?i)(server\.host|bind|listen|host)\s*[:=]\s*[""']?0\.0\.0\.0", RegexOptions.Compiled));
                if (!hasDefault && SecretAssignment.IsMatch(line) && !isComment)
                {
                    findings.Add(CreateFinding("PLAINTEXT-SECRET", Severity.High, file, lineNumber,
                        "A credential-like value is assigned directly in configuration.", line));
                }
            }
        }
        return findings;
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        if (!Directory.Exists(root)) yield break;
        var pending = new Stack<string>();
        pending.Push(Path.GetFullPath(root));
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> children;
            try { children = Directory.EnumerateFileSystemEntries(directory); }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var child in children)
            {
                if (Directory.Exists(child))
                {
                    if (!SkipDirectories.Contains(Path.GetFileName(child), StringComparer.OrdinalIgnoreCase)) pending.Push(child);
                    continue;
                }
                if (Extensions.Contains(Path.GetExtension(child), StringComparer.OrdinalIgnoreCase)) yield return child;
            }
        }
    }

    private static void AddPattern(List<Finding> findings, string file, int line, string text,
        string rule, Severity severity, string message, Regex pattern)
    {
        if (pattern.IsMatch(text)) findings.Add(CreateFinding(rule, severity, file, line, message, text));
    }

    private static Finding CreateFinding(string rule, Severity severity, string file, int line, string message, string evidence)
    {
        return new Finding(rule, severity, file, line, message, Redact(evidence));
    }

    private static string Redact(string evidence)
    {
        var redacted = Regex.Replace(evidence, @"(?i)((?:password|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+", "$1[REDACTED]");
        return redacted.Contains("changeme", StringComparison.OrdinalIgnoreCase) ? "placeholder credential reference [REDACTED]" : redacted.Trim();
    }
}

static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static int Main(string[] args)
    {
        var root = GetOption(args, "--path") ?? Directory.GetCurrentDirectory();
        var format = (GetOption(args, "--format") ?? "text").ToLowerInvariant();
        var failOn = ParseSeverity(GetOption(args, "--fail-on") ?? "high");
        var findings = SecurityAudit.Scan(root);

        if (format == "json")
        {
            Console.WriteLine(JsonSerializer.Serialize(findings, JsonOptions));
        }
        else
        {
            Console.WriteLine($"Honeypot Security Audit | {Path.GetFullPath(root)}");
            Console.WriteLine(new string('-', 72));
            if (findings.Count == 0) Console.WriteLine("PASS  No configured security rules were violated.");
            foreach (var finding in findings.OrderByDescending(item => item.Severity).ThenBy(item => item.File))
            {
                Console.WriteLine($"{finding.Severity.ToString().ToUpperInvariant(),-8} {finding.Rule,-28} {finding.File}:{finding.Line}");
                Console.WriteLine($"         {finding.Message} | {finding.Evidence}");
            }
            Console.WriteLine(new string('-', 72));
            Console.WriteLine($"{findings.Count} finding(s); failing threshold: {failOn.ToString().ToUpperInvariant()}");
        }

        return findings.Any(finding => finding.Severity >= failOn) ? 1 : 0;
    }

    private static string? GetOption(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static Severity ParseSeverity(string value)
    {
        return Enum.TryParse<Severity>(value, true, out var severity) ? severity : Severity.High;
    }
}