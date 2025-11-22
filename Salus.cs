using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Salus
{
    // --- 4. Error & Logging System ---
    public abstract class SalusException : Exception
    {
        protected SalusException(string message) : base(message) { }
        protected SalusException(string message, Exception? innerException) : base(message, innerException) { }
    }

    public class SyntaxError : SalusException
    {
        public SyntaxError(string message) : base(message) { }
        public SyntaxError(string message, Exception? innerException = null) : base(message, innerException) { }
    }

    public class RuntimeError : SalusException
    {
        public RuntimeError(string message) : base(message) { }
        public RuntimeError(string message, Exception? innerException = null) : base(message, innerException) { }
    }

    public class SecurityError : SalusException
    {
        public SecurityError(string message) : base(message) { }
        public SecurityError(string message, Exception? innerException = null) : base(message, innerException) { }
    }

    public static class LogSystem
    {
        public static void Info(string message) => Console.WriteLine($"[INFO] {message}");
        public static void Warning(string message) => Console.WriteLine($"[WARN] {message}");
        public static void Error(string message, Exception? ex = null)
        {
            Console.Error.WriteLine($"[ERROR] {message}");
            if (ex != null) Console.Error.WriteLine(ex.ToString());
            // TODO: Implement encryption and signing for logs
        }

        public static void SecurityEvent(string message, string? details = null)
        {
            Console.WriteLine($"[SECURITY] {message} {details}");
            // TODO: Ensure encryption and signing for security logs
        }
    }

    // --- 1. Core Interpreter (Salus Engine) ---
    public abstract class AstNode { }
    public class ExpressionNode : AstNode { }
    public class StatementNode : AstNode { }

    public class Parser
    {
        public AstNode Parse(string code)
        {
            LogSystem.Info("Parsing code...");
            // TODO: Implement actual parsing logic
            return new StatementNode(); // Placeholder
        }
    }

    public class Interpreter
    {
        private readonly SecurityManager _securityManager;
        private readonly ModuleManager _moduleManager;
        private readonly AsyncRuntime _asyncRuntime;

        public Interpreter(SecurityManager securityManager, ModuleManager moduleManager, AsyncRuntime asyncRuntime)
        {
            _securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
            _moduleManager = moduleManager ?? throw new ArgumentNullException(nameof(moduleManager));
            _asyncRuntime = asyncRuntime ?? throw new ArgumentNullException(nameof(asyncRuntime));
        }

        public async Task<object?> Execute(AstNode ast)
        {
            LogSystem.Info("Executing AST...");
            // TODO: Implement AST traversal and execution
            await Task.Delay(1); // Simulate async work
            return null; // Placeholder for result
        }

        public async Task<object?> Eval(string code)
        {
            AstNode ast = new Parser().Parse(code);
            return await Execute(ast);
        }
    }

    // --- 2. Module Manager ---
    public class ModuleManager
    {
        private readonly SecurityManager _securityManager;
        private readonly Dictionary<string, object> _loadedModules = new Dictionary<string, object>();

        public ModuleManager(SecurityManager securityManager)
        {
            _securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
        }

        public object LoadModule(string moduleName, string path)
        {
            LogSystem.Info($"Loading module: {moduleName} from {path}");
            if (!_securityManager.VerifyPluginSignature(path))
            {
                throw new SecurityError($"Module '{moduleName}' signature verification failed.");
            }
            // TODO: Implement actual plugin loading (e.g., Assembly.LoadFrom, Reflection)
            // Ensure sandboxing (IPC/RPC) is considered here for security
            object module = new object(); // Placeholder for loaded module
            _loadedModules[moduleName] = module;
            return module;
        }
    }

    // --- 3. External Command Bridge Layer ---
    public class ExternalCommandBridge
    {
        private readonly SecurityManager _securityManager;

        public ExternalCommandBridge(SecurityManager securityManager)
        {
            _securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
        }

        public async Task<string> ExecuteSystemCommand(string command, string arguments, string workingDirectory)
        {
            LogSystem.SecurityEvent($"Attempting to execute external command: {command} {arguments}");

            if (!_securityManager.CanExecuteExternalCommand(command, arguments, workingDirectory))
            {
                throw new SecurityError($"Execution of command '{command}' is denied by security policy.");
            }

            using (System.Diagnostics.Process process = new System.Diagnostics.Process())
            {
                process.StartInfo.FileName = command;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.WorkingDirectory = workingDirectory;

                LogSystem.Info($"Executing: {command} {arguments} in {workingDirectory}");
                process.Start();

                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                if (process.ExitCode != 0)
                {
                    LogSystem.Error($"Command '{command}' exited with code {process.ExitCode}. Error: {error}");
                    throw new RuntimeError($"External command failed: {error}");
                }
                LogSystem.Info($"Command '{command}' completed successfully.");
                return output;
            }
        }

        public async Task<string> CallApi(string url, System.Net.Http.HttpMethod method, string? body = null)
        {
            if (!_securityManager.CanAccessNetworkResource(url))
            {
                throw new SecurityError($"Network access to '{url}' is denied by security policy.");
            }
            LogSystem.Info($"Calling API: {method} {url}");
            using (HttpClient client = new HttpClient())
            {
                HttpRequestMessage request = new HttpRequestMessage(method, url);

                if (body != null && (method == System.Net.Http.HttpMethod.Post || method == System.Net.Http.HttpMethod.Put))
                {
                    request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                }

                HttpResponseMessage response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync();
            }
        }
    }

    // --- 4. Security & Permission Model ---
    public class SecurityManager
    {
        private bool _isSandboxActive = true;
        private List<string> _allowedPaths = new List<string>();

        public void ActivateSandbox() { _isSandboxActive = true; LogSystem.Info("Sandbox activated."); }
        public void DeactivateSandbox() { _isSandboxActive = false; LogSystem.Info("Sandbox deactivated (DANGEROUS)."); }

        public void SetAllowedPaths(IEnumerable<string> paths)
        {
            _allowedPaths = paths.Select(p => Path.GetFullPath(p)).ToList();
            LogSystem.Info($"Allowed paths set: {string.Join(", ", _allowedPaths)}");
        }

        public bool CanExecuteExternalCommand(string command, string arguments, string workingDirectory)
        {
            if (!_isSandboxActive) return true;

            if (command.Contains("rm", StringComparison.OrdinalIgnoreCase) || command.Contains("format", StringComparison.OrdinalIgnoreCase)) return false;
            // TODO: Implement robust policy based on configuration, user permissions, etc.
            return true;
        }

        public bool CanAccessNetworkResource(string url)
        {
            if (!_isSandboxActive) return true;
            // TODO: Implement network access policy (whitelist/blacklist URLs/domains)
            return url.StartsWith("https://api.salus.dev/", StringComparison.OrdinalIgnoreCase); // Example
        }

        public bool CanAccessFileSystem(string path, FileAccess access)
        {
            if (!_isSandboxActive) return true;

            string fullPath = Path.GetFullPath(path);
            if (_allowedPaths.Any(allowedPath => fullPath.StartsWith(allowedPath, StringComparison.OrdinalIgnoreCase)))
            {
                // TODO: Add more fine-grained access checks (e.g., read vs write)
                return true;
            }

            LogSystem.SecurityEvent($"File system access denied for: {path} (Access: {access})");
            return false;
        }

        public bool VerifyPluginSignature(string pluginPath)
        {
            LogSystem.Info($"Verifying plugin signature for: {pluginPath}");
            // TODO: Implement actual digital signature verification
            using (var sha256 = SHA256.Create())
            using (var fs = File.OpenRead(pluginPath))
            {
                byte[] hash = sha256.ComputeHash(fs);
                // In a real scenario, compare 'hash' with a stored/embedded signature.
                // This is a placeholder and not actual cryptographic signature verification.
            }
            LogSystem.SecurityEvent($"Plugin signature verification successful (placeholder): {pluginPath}");
            return true;
        }
    }

    // --- 5. Async Execution Model ---
    public class AsyncRuntime
    {
        private readonly List<Task> _runningTasks = new List<Task>();
        private readonly object _lock = new object();

        public void ScheduleTask(Task task)
        {
            lock (_lock)
            {
                _runningTasks.Add(task);
                LogSystem.Info($"Task scheduled. Total running tasks: {_runningTasks.Count}");
            }
        }

        public async Task RunEventLoop()
        {
            LogSystem.Info("Starting event loop...");
            while (true)
            {
                List<Task> currentTasks;
                lock (_lock)
                {
                    _runningTasks.RemoveAll(t => t.IsCompleted);
                    currentTasks = _runningTasks.ToList();
                }

                if (!currentTasks.Any())
                {
                    break; // No more tasks, event loop can finish
                }

                await Task.WhenAny(currentTasks.Append(Task.Delay(100)));
                LogSystem.Info($"Event loop iteration. Remaining tasks: {currentTasks.Count}");
            }
            LogSystem.Info("Event loop finished.");
        }
    }

    // --- 6. CLI Interaction Layer ---
    public class CliInteraction
    {
        private readonly ExternalCommandBridge _commandBridge;
        private readonly Interpreter _interpreter;
        private readonly SecurityManager _securityManager;

        public CliInteraction(ExternalCommandBridge commandBridge, Interpreter interpreter, SecurityManager securityManager)
        {
            _commandBridge = commandBridge ?? throw new ArgumentNullException(nameof(commandBridge));
            _interpreter = interpreter ?? throw new ArgumentNullException(nameof(interpreter));
            _securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
        }

        public async Task RunInteractiveMode()
        {
            LogSystem.Info("Entering interactive mode (Salus REPL). Type 'exit' to quit.");
            while (true)
            {
                Console.Write("salus> ");
                string? input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input)) continue;
                if (input.Trim().ToLower() == "exit") break;

                try
                {
                    if (input.StartsWith("!"))
                    {
                        string cmd = input.Substring(1).Trim();
                        string[] parts = cmd.Split(' ', 2);
                        string commandName = parts[0];
                        string args = parts.Length > 1 ? parts[1] : "";
                        string result = await _commandBridge.ExecuteSystemCommand(commandName, args, Directory.GetCurrentDirectory());
                        Console.WriteLine(result);
                    }
                    else
                    {
                        object? result = await _interpreter.Eval(input);
                        if (result != null)
                        {
                            Console.WriteLine($"=> {result}");
                        }
                    }
                }
                catch (SalusException ex)
                {
                    LogSystem.Error($"Salus Error: {ex.Message}", ex);
                }
                catch (Exception ex)
                {
                    LogSystem.Error($"Unhandled System Error: {ex.Message}", ex);
                }
            }
        }

        public void SetupCliFeatures()
        {
            LogSystem.Info("CLI features (auto-completion, highlighting) are not yet fully implemented in this sample.");
        }
    }

    public class Program
    {
        public static async Task<int> Main(string[] args)
        {
            var securityManager = new SecurityManager();
            var moduleManager = new ModuleManager(securityManager);
            var asyncRuntime = new AsyncRuntime();
            var externalCommandBridge = new ExternalCommandBridge(securityManager);
            var interpreter = new Interpreter(securityManager, moduleManager, asyncRuntime);
            var cliInteraction = new CliInteraction(externalCommandBridge, interpreter, securityManager);

            var rootCommand = new RootCommand("Salus - The multi-platform script interpreter.")
            {
                new Option<bool>(
                    "--sandbox",
                    getDefaultValue: () => true,
                    description: "Enable security sandbox for execution."
                ),
                new Option<string[]?>(
                    "--allow-path",
                    description: "Specify paths allowed in sandbox mode (comma-separated)."
                )
            };

            var runCommand = new Command("run", "Execute a Salus script file.")
            {
                new Argument<FileInfo>("script-file", "The Salus script file to execute.")
            };
            runCommand.SetHandler(async (context) =>
            {
                FileInfo file = context.ParseResult.GetValueForArgument(runCommand.Arguments.First(a => a.Name == "script-file")) as FileInfo ?? throw new ArgumentException("Script file argument is missing or invalid.");
                bool sandbox = context.ParseResult.GetValueForOption<bool>(rootCommand.Options.First(o => o.Name == "sandbox"));
                string[]? allowedPaths = context.ParseResult.GetValueForOption<string[]?>(rootCommand.Options.First(o => o.Name == "allow-path"));

                if (sandbox) securityManager.ActivateSandbox(); else securityManager.DeactivateSandbox();
                if (allowedPaths != null) securityManager.SetAllowedPaths(allowedPaths);

                try
                {
                    if (!file.Exists)
                    {
                        LogSystem.Error($"Error: Script file not found at '{file.FullName}'");
                        context.ExitCode = 1;
                        return;
                    }
                    string code = await File.ReadAllTextAsync(file.FullName);
                    await interpreter.Eval(code);
                }
                catch (SalusException ex)
                {
                    LogSystem.Error($"Salus Script Error: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
                catch (Exception ex)
                {
                    LogSystem.Error($"Unhandled System Error during script execution: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
            });

            var execCommand = new Command("exec", "Execute a Salus code string directly.")
            {
                new Argument<string>("code", "The Salus code string to execute.")
            };
            execCommand.SetHandler(async (context) =>
            {
                string code = context.ParseResult.GetValueForArgument(execCommand.Arguments.First(a => a.Name == "code")) as string ?? throw new ArgumentException("Code argument is missing.");
                bool sandbox = context.ParseResult.GetValueForOption<bool>(rootCommand.Options.First(o => o.Name == "sandbox"));
                string[]? allowedPaths = context.ParseResult.GetValueForOption<string[]?>(rootCommand.Options.First(o => o.Name == "allow-path"));

                if (sandbox) securityManager.ActivateSandbox(); else securityManager.DeactivateSandbox();
                if (allowedPaths != null) securityManager.SetAllowedPaths(allowedPaths);

                try
                {
                    await interpreter.Eval(code);
                }
                catch (SalusException ex)
                {
                    LogSystem.Error($"Salus Exec Error: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
                catch (Exception ex)
                {
                    LogSystem.Error($"Unhandled System Error during direct execution: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
            });

            var evalCommand = new Command("eval", "Evaluate a Salus expression and print its result.")
            {
                new Argument<string>("expression", "The Salus expression to evaluate.")
            };
            evalCommand.SetHandler(async (context) =>
            {
                string expression = context.ParseResult.GetValueForArgument(evalCommand.Arguments.First(a => a.Name == "expression")) as string ?? throw new ArgumentException("Expression argument is missing.");
                bool sandbox = context.ParseResult.GetValueForOption<bool>(rootCommand.Options.First(o => o.Name == "sandbox"));
                string[]? allowedPaths = context.ParseResult.GetValueForOption<string[]?>(rootCommand.Options.First(o => o.Name == "allow-path"));

                if (sandbox) securityManager.ActivateSandbox(); else securityManager.DeactivateSandbox();
                if (allowedPaths != null) securityManager.SetAllowedPaths(allowedPaths);

                try
                {
                    object? result = await interpreter.Eval(expression);
                    if (result != null)
                    {
                        Console.WriteLine($"=> {result}");
                    }
                }
                catch (SalusException ex)
                {
                    LogSystem.Error($"Salus Eval Error: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
                catch (Exception ex)
                {
                    LogSystem.Error($"Unhandled System Error during evaluation: {ex.Message}", ex);
                    context.ExitCode = 1;
                }
            });

            rootCommand.SetHandler(async (context) =>
            {
                bool sandbox = context.ParseResult.GetValueForOption<bool>(rootCommand.Options.First(o => o.Name == "sandbox"));
                string[]? allowedPaths = context.ParseResult.GetValueForOption<string[]?>(rootCommand.Options.First(o => o.Name == "allow-path"));

                if (sandbox) securityManager.ActivateSandbox(); else securityManager.DeactivateSandbox();
                if (allowedPaths != null) securityManager.SetAllowedPaths(allowedPaths);

                cliInteraction.SetupCliFeatures();
                await cliInteraction.RunInteractiveMode();
            });

            rootCommand.AddCommand(runCommand);
            rootCommand.AddCommand(execCommand);
            rootCommand.AddCommand(evalCommand);

            return await rootCommand.InvokeAsync(args);
        }
    }
}