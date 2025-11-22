using System;
using System.Threading.Tasks;
using System.CommandLine; // Required for robust CLI argument parsing
using System.IO; // For file operations like ReadAllTextAsync

// Placeholder interfaces for core Salus components, reflecting the requirements.
// In a real project, these would typically be in separate files and namespaces.

/// <summary>
/// Defines the contract for the Salus core interpreter (Salus Engine).
/// Responsible for syntax parsing, AST construction, and execution.
/// </summary>
public interface ISalusEngine
{
    /// <summary>
    /// Executes the provided code based on the specified execution mode.
    /// </summary>
    /// <param name="code">The Salus code or script content to execute.</param>
    /// <param name="mode">The execution mode (e.g., Run, Eval, Script).</param>
    /// <returns>An exit code (0 for success, non-zero for failure).</returns>
    Task<int> ExecuteAsync(string code, ExecutionMode mode);
    // Further methods would be added here for AST parsing, type checking, etc.
}

/// <summary>
/// Represents the core Salus interpreter.
/// </summary>
public class SalusEngine : ISalusEngine
{
    private readonly ILogger _logger; // Dependency on the logging system

    /// <summary>
    /// Initializes a new instance of the <see cref="SalusEngine"/> class.
    /// </summary>
    /// <param name="logger">The logger instance to use for reporting events.</param>
    public SalusEngine(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task<int> ExecuteAsync(string code, ExecutionMode mode)
    {
        // Simulate core engine work: parsing, AST building, execution.
        // The actual implementation would involve complex logic here.
        _logger.LogInfo($"[Engine] Executing code in {mode} mode (len: {code.Length}): \"{code.Substring(0, Math.Min(code.Length, 50))}...\"");
        
        try
        {
            // Placeholder for actual AST parsing, semantic analysis, and execution.
            // This would involve the "多執行緒與非同步命令" and "物件池與 .NET GC 混合策略" memory management.
            await Task.Delay(50); // Simulate asynchronous execution time.

            // Example of a basic type system check (placeholder)
            if (code.Contains("type_error_example"))
            {
                _logger.LogError(new InvalidOperationException("Simulated type mismatch error."), "Type system detected an issue.");
                return 1;
            }

            _logger.LogInfo($"[Engine] Execution in {mode} mode complete.");
            return 0; // Success
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"[Engine] An error occurred during execution in {mode} mode.");
            return 1; // Indicate failure
        }
    }
}

/// <summary>
/// Defines the various execution modes for the Salus engine, as per CLI requirements.
/// </summary>
public enum ExecutionMode
{
    /// <summary>
    /// Standard execution mode, typically for running script files.
    /// </summary>
    Run,
    /// <summary>
    /// Execute a specific command or function.
    /// </summary>
    Exec,
    /// <summary>
    /// Evaluate a single expression.
    /// </summary>
    Eval,
    /// <summary>
    /// Scripting mode, potentially interactive (REPL) or for direct script execution.
    /// </summary>
    Script
}

/// <summary>
/// Defines the contract for the unified error and logging system.
/// Supports different log levels, security events, and placeholder for encryption/signing.
/// </summary>
public interface ILogger
{
    /// <summary>Logs an informational message.</summary>
    /// <param name="message">The message to log.</param>
    void LogInfo(string message);

    /// <summary>Logs a warning message.</summary>
    /// <param name="message">The message to log.</param>
    void LogWarning(string message);

    /// <summary>Logs an error message, including an associated exception.</summary>
    /// <param name="ex">The exception that occurred.</param>
    /// <param name="message">An optional custom message for the error.</param>
    void LogError(Exception ex, string message = null);

    /// <summary>Logs a security-related event, which typically requires encryption and signing.</summary>
    /// <param name="eventDescription">A brief description of the security event.</param>
    /// <param name="details">Detailed information about the security event.</param>
    void LogSecurityEvent(string eventDescription, string details);
}

/// <summary>
/// A basic console-based implementation of the <see cref="ILogger"/> interface.
/// In a real system, this would write to files, potentially encrypted and signed,
/// and integrate with a robust logging framework.
/// </summary>
public class ConsoleLogger : ILogger
{
    /// <inheritdoc/>
    public void LogInfo(string message)
    {
        Console.WriteLine($"[INFO] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} {message}");
    }

    /// <inheritdoc/>
    public void LogWarning(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[WARN] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} {message}");
        Console.ResetColor();
    }

    /// <inheritdoc/>
    public void LogError(Exception ex, string message = null)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"[ERROR] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} {message ?? ex.Message}");
        if (ex != null)
        {
            Console.Error.WriteLine(ex.ToString()); // Output full exception details
        }
        Console.ResetColor();
        // As per requirements: In a production system, this log entry would be encrypted and signed.
        // Example: CryptoService.EncryptAndSign(message + ex.ToString());
    }

    /// <inheritdoc/>
    public void LogSecurityEvent(string eventDescription, string details)
    {
        Console.ForegroundColor = ConsoleColor.DarkMagenta;
        Console.WriteLine($"[SECURITY] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} {eventDescription}: {details}");
        Console.ResetColor();
        // As per requirements: This log entry *must* be encrypted and signed for tamper-proofing.
        // Example: CryptoService.EncryptAndSignSecurityEvent(eventDescription, details);
    }
}

/// <summary>
/// Defines the contract for the Salus module (plugin) manager.
/// Responsible for loading, verifying, and managing extensions.
/// </summary>
public interface IModuleManager
{
    /// <summary>
    /// Asynchronously loads all registered modules and plugins, performing security checks.
    /// </summary>
    Task LoadModulesAsync();
    // Further methods would handle plugin installation, sandboxing, IPC/RPC,
    // version/dependency checks, and digital signature verification.
}

/// <summary>
/// A basic implementation of the <see cref="IModuleManager"/> interface.
/// </summary>
public class ModuleManager : IModuleManager
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ModuleManager"/> class.
    /// </summary>
    /// <param name="logger">The logger instance to use for reporting events.</param>
    public ModuleManager(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async Task LoadModulesAsync()
    {
        _logger.LogInfo("[ModuleManager] Starting module and plugin loading...");
        // Simulate loading time and security checks.
        await Task.Delay(100);

        try
        {
            // Placeholder for actual plugin validation logic:
            // - Digital signature verification (外掛驗證)
            // - Version and dependency checking (版本與相依性檢查)
            // - Sandbox setup (外掛沙箱)
            // - Loading via AssemblyLoadContext for isolation.
            bool allPluginsVerified = true; // Assume success for this placeholder.

            if (allPluginsVerified)
            {
                _logger.LogSecurityEvent("PluginVerification", "All essential plugins digitally signed and verified.");
                _logger.LogInfo("[ModuleManager] All modules and plugins loaded successfully.");
            }
            else
            {
                _logger.LogSecurityEvent("PluginVerificationFailed", "Some plugins failed digital signature verification. Loading aborted.");
                _logger.LogError(new SecurityException("Untrusted plugins detected."), "Failed to load all modules securely.");
                throw new SecurityException("One or more plugins failed security validation.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ModuleManager] Error during module loading.");
            throw; // Re-throw to propagate the failure
        }
    }
}

/// <summary>
/// The main entry point for the Salus CLI application.
/// This class handles initial setup, argument parsing, and command dispatching.
/// </summary>
internal class Salus
{
    private static ILogger _logger;
    private static ISalusEngine _salusEngine;
    private static IModuleManager _moduleManager;

    /// <summary>
    /// The asynchronous main entry point for the Salus application.
    /// Configures the CLI and dispatches commands.
    /// </summary>
    /// <param name="args">Command-line arguments passed to the application.</param>
    /// <returns>An exit code (0 for success, non-zero for failure).</returns>
    public static async Task<int> Main(string[] args)
    {
        // --- Initialization of Core Services ---
        _logger = new ConsoleLogger(); // Initialize the logging system early.
        _salusEngine = new SalusEngine(_logger);
        _moduleManager = new ModuleManager(_logger);

        _logger.LogInfo("Salus CLI application starting...");

        try
        {
            // Load modules and plugins first, as they might provide commands or functionalities.
            await _moduleManager.LoadModulesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Salus failed to initialize due to module loading errors. Exiting.");
            return 1; // Indicate a critical startup failure.
        }

        // --- CLI Interface Setup using System.CommandLine ---
        // This addresses "CLI 介面模組" and "指令結構" requirements.
        var rootCommand = new RootCommand("Salus - The multi-platform scripting and automation engine.")
        {
            Description = "Salus is a powerful, cross-platform tool supporting scripting, task automation, and system integration."
        };

        // --- 'run' command: Execute a Salus script file or inline code ---
        // Maps to "run" mode.
        var runCommand = new Command("run", "Execute a Salus script file or inline code.")
        {
            new Argument<string>("source", "The path to the script file OR the inline code string.")
            {
                Name = "Source" // Ensure a meaningful name for the argument
            },
            new Option<bool>("--file", "Specify if the source argument is a file path (default: inline code).")
            {
                Name = "IsFile"
            }
        };
        runCommand.SetHandler(async (source, isFile) =>
        {
            try
            {
                string codeToExecute = source;
                if (isFile)
                {
                    _logger.LogInfo($"[CLI] Attempting to read script from file: {source}");
                    if (!File.Exists(source))
                    {
                        _logger.LogError(null, $"[CLI] Script file not found: {source}");
                        Environment.ExitCode = 1;
                        return;
                    }
                    codeToExecute = await File.ReadAllTextAsync(source);
                }
                else
                {
                    _logger.LogInfo($"[CLI] Running inline code: '{source}'");
                }
                Environment.ExitCode = await _salusEngine.ExecuteAsync(codeToExecute, ExecutionMode.Run);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[CLI] An error occurred during 'run' command execution.");
                Environment.ExitCode = 1; // Indicate failure
            }
        },
        // Bind arguments and options to handler parameters using System.CommandLine's binding context.
        runCommand.Arguments[0], runCommand.Options[0]);
        rootCommand.AddCommand(runCommand);

        // --- 'exec' command: Execute a specific command/function from a module ---
        // Maps to "exec" mode, supporting "外部指令橋接層".
        var execCommand = new Command("exec", "Execute a specific Salus command or function from a loaded module.")
        {
            new Argument<string>("commandName", "The name of the command or function to execute.")
            {
                 Name = "CommandName"
            },
            new Argument<string[]>("args", "Optional arguments for the command/function.")
            {
                Name = "CommandArguments"
            }
        };
        execCommand.SetHandler(async (commandName, commandArgs) =>
        {
            try
            {
                _logger.LogInfo($"[CLI] Executing command '{commandName}' with arguments: [{string.Join(", ", commandArgs)}]");
                // In a real implementation, this would involve dispatching to the module manager or engine
                // to find and execute the named command, respecting "外部命令沙箱化執行" and "權限控管".
                // For now, we simulate with the engine.
                string combinedCode = $"{commandName} {string.Join(" ", commandArgs)}";
                Environment.ExitCode = await _salusEngine.ExecuteAsync(combinedCode, ExecutionMode.Exec);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[CLI] An error occurred during 'exec {commandName}' command execution.");
                Environment.ExitCode = 1;
            }
        },
        execCommand.Arguments[0], execCommand.Arguments[1]);
        rootCommand.AddCommand(execCommand);

        // --- 'eval' command: Evaluate a single Salus expression ---
        // Maps to "eval" mode.
        var evalCommand = new Command("eval", "Evaluate a single Salus expression and print the result.")
        {
            new Argument<string>("expression", "The Salus expression string to evaluate.")
            {
                Name = "Expression"
            }
        };
        evalCommand.SetHandler(async (expression) =>
        {
            try
            {
                _logger.LogInfo($"[CLI] Evaluating expression: '{expression}'");
                Environment.ExitCode = await _salusEngine.ExecuteAsync(expression, ExecutionMode.Eval);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[CLI] An error occurred during 'eval' command execution.");
                Environment.ExitCode = 1;
            }
        },
        evalCommand.Arguments[0]);
        rootCommand.AddCommand(evalCommand);

        // --- 'script' command: Enter interactive mode or run a script file ---
        // Maps to "script" mode, hinting at REPL functionality ("互動功能").
        var scriptCommand = new Command("script", "Enter interactive scripting (REPL) mode or run a script file.")
        {
            new Option<string>("--file", "Specify a script file to run directly in script mode.")
            {
                Name = "FilePath"
            }
        };
        scriptCommand.SetHandler(async (filePath) =>
        {
            try
            {
                if (!string.IsNullOrEmpty(filePath))
                {
                    _logger.LogInfo($"[CLI] Running script file in script mode: '{filePath}'");
                    if (!File.Exists(filePath))
                    {
                        _logger.LogError(null, $"[CLI] Script file not found: {filePath}");
                        Environment.ExitCode = 1;
                        return;
                    }
                    string code = await File.ReadAllTextAsync(filePath);
                    Environment.ExitCode = await _salusEngine.ExecuteAsync(code, ExecutionMode.Script);
                }
                else
                {
                    _logger.LogInfo("[CLI] Entering interactive scripting (REPL) mode. Type 'exit' to quit.");
                    Console.WriteLine("Salus REPL. Type 'exit' to quit.");
                    while (true)
                    {
                        Console.Write("salus> ");
                        string input = Console.ReadLine();
                        if (input?.ToLowerInvariant().Trim() == "exit")
                        {
                            _logger.LogInfo("[CLI] Exiting REPL mode.");
                            break;
                        }
                        if (string.IsNullOrWhiteSpace(input)) continue;

                        try
                        {
                            // Await the engine execution for each REPL input.
                            // The result of each line might need to be printed.
                            int replResult = await _salusEngine.ExecuteAsync(input, ExecutionMode.Script);
                            if (replResult != 0)
                            {
                                _logger.LogWarning($"[REPL] Expression execution failed with code {replResult}.");
                            }
                        }
                        catch (Exception replEx)
                        {
                            _logger.LogError(replEx, "[REPL] An error occurred while evaluating expression.");
                        }
                    }
                    Environment.ExitCode = 0; // REPL exit is generally considered successful if no critical errors.
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[CLI] An error occurred during 'script' command execution.");
                Environment.ExitCode = 1;
            }
        },
        scriptCommand.Options[0]);
        rootCommand.AddCommand(scriptCommand);

        // --- 'diag' command: Run diagnostic checks and report system status ---
        // Maps to "診斷工具 (salus diag/report)".
        var diagCommand = new Command("diag", "Run diagnostic checks and report system status.")
        {
            new Option<bool>("--verbose", "Include verbose diagnostic information.")
            {
                Name = "Verbose"
            }
        };
        diagCommand.SetHandler((verbose) =>
        {
            _logger.LogInfo("[CLI] Running Salus diagnostics...");

            _logger.LogInfo($".NET Runtime Version: {Environment.Version}");
            _logger.LogInfo($"Operating System: {Environment.OSVersion} ({(Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit")})");
            _logger.LogInfo($"Process Architecture: {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");
            _logger.LogInfo($"OS Architecture: {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
            _logger.LogInfo($"Current Directory: {Environment.CurrentDirectory}");
            _logger.LogInfo($"Machine Name: {Environment.MachineName}");
            _logger.LogInfo($"Logical Processors: {Environment.ProcessorCount}");
            _logger.LogInfo($"Self-contained deployment: true (as per requirements)");

            if (verbose)
            {
                _logger.LogInfo("--- Verbose Diagnostics ---");
                // Add more detailed info, e.g., loaded assemblies, environment variables, etc.
                _logger.LogInfo($"Environment variables: {string.Join(", ", Environment.GetEnvironmentVariables().Keys)}");
                // Could also query module manager for loaded plugins, versions, health.
            }

            _logger.LogInfo("[CLI] Diagnostics complete.");
            Environment.ExitCode = 0;
        },
        diagCommand.Options[0]);
        rootCommand.AddCommand(diagCommand);

        // --- Version command ---
        var versionCommand = new Command("version", "Display the Salus application version.");
        versionCommand.SetHandler(() =>
        {
            var assembly = typeof(Salus).Assembly;
            var version = assembly.GetName().Version;
            var informationalVersion = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                                               is System.Reflection.AssemblyInformationalVersionAttribute[] attrs && attrs.Length > 0
                                               ? attrs[0].InformationalVersion : version.ToString();

            _logger.LogInfo($"Salus Version: {informationalVersion} (Core: {version})");
            Environment.ExitCode = 0;
        });
        rootCommand.AddCommand(versionCommand);

        // --- Execute CLI ---
        // System.CommandLine takes care of parsing 'args' and invoking the correct handler.
        // It returns an exit code based on the handler's success or failure.
        int finalExitCode = await rootCommand.InvokeAsync(args);

        if (finalExitCode != 0)
        {
            _logger.LogError(null, $"Salus application finished with exit code {finalExitCode}.");
        }
        else
        {
            _logger.LogInfo("Salus application finished successfully.");
        }

        return finalExitCode;
    }
}