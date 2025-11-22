using System;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Hosting;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Salus - A powerful, secure, cross-platform scripting engine.
// This file serves as the application's entry point, handling host setup,
// dependency injection, logging, and command-line argument parsing.

// 1. Build the Host:
// The Host is responsible for application lifetime, configuration, logging, and dependency injection.
// It's the standard way to build modern .NET applications, especially those with services.
var builder = Host.CreateDefaultBuilder(args);

// Configure services for dependency injection
builder.ConfigureServices((hostContext, services) =>
{
    // Register application-specific services here.
    // This is where components like the Salus Engine, CLI services,
    // Module Manager, Error/Log System, etc., would be registered
    // following the architectural requirements.

    // Register the main application logic wrapper.
    // Using `SalusApp` as the context for `ILogger<T>` provides logical grouping.
    services.AddSingleton<SalusApp>(); 
    
    // Example: Register core Salus components (actual implementation would be in separate files)
    // services.AddSingleton<ISalusEngine, SalusEngine>(); 
    // services.AddSingleton<IModuleManager, ModuleManager>();
    // services.AddSingleton<IErrorService, ErrorService>();
    // services.AddSingleton<ISecurityManager, SecurityManager>();
    // services.AddSingleton<ICliService, CliService>(); // For more advanced CLI features like history, auto-completion
});

// Configure logging (default builder already sets up console logging, but can be customized)
builder.ConfigureLogging(logging =>
{
    logging.ClearProviders(); // Clear default providers to configure explicitly
    logging.AddConsole();     // Add console logging as a primary output
    // Based on requirements I-5 (encrypted logs), a custom logger provider would be needed for production.
    // Example: logging.AddProvider(new EncryptedFileLoggerProvider());
    logging.SetMinimumLevel(LogLevel.Information); // Default log level, can be overridden by config or CLI option
    logging.AddFilter("System.CommandLine", LogLevel.Warning); // Reduce verbosity from System.CommandLine
});

var host = builder.Build();

// Retrieve the logger for the entry point context.
var logger = host.Services.GetRequiredService<ILogger<SalusApp>>();

// 2. Setup CLI parser (System.CommandLine)
// The requirements explicitly mention CLI commands like run, exec, eval, script, and help.
var rootCommand = new RootCommand("Salus - A powerful, secure, cross-platform scripting engine.")
{
    // Global options available for all commands.
    new Option<bool>("--verbose", "Enable verbose output for detailed logging.")
    {
        ArgumentHelpName = "boolean",
        IsRequired = false
    },
    new Option<string>("--config", "Specify a custom configuration file path.")
    {
        ArgumentHelpName = "path",
        IsRequired = false
    }
};

// 'run' command: Execute a Salus script file.
var runCommand = new Command("run", "Execute a Salus script file.")
{
    new Argument<string>("scriptPath", "Path to the Salus script file.")
};
runCommand.SetHandler(async (string scriptPath, bool verbose, ILogger<SalusApp> log) =>
{
    if (verbose) log.LogDebug("Verbose output enabled.");
    log.LogInformation($"Running script: {scriptPath}");
    // TODO: Integrate with SalusEngine to parse and execute the script.
    await Task.Delay(100); // Simulate asynchronous work
    log.LogInformation($"Script '{scriptPath}' finished successfully.");
}, runCommand.GetInvocationBuilder().GetAction<string, bool, ILogger<SalusApp>>()); // Binder for System.CommandLine

// 'exec' command: Execute a single Salus command string.
var execCommand = new Command("exec", "Execute a single Salus command string.")
{
    new Argument<string>("commandString", "The Salus command string to execute.")
};
execCommand.SetHandler(async (string commandString, bool verbose, ILogger<SalusApp> log) =>
{
    if (verbose) log.LogDebug("Verbose output enabled.");
    log.LogInformation($"Executing command: {commandString}");
    // TODO: Integrate with SalusEngine to parse and execute the command string.
    await Task.Delay(100); // Simulate asynchronous work
    log.LogInformation($"Command '{commandString}' finished successfully.");
}, execCommand.GetInvocationBuilder().GetAction<string, bool, ILogger<SalusApp>>());

// 'eval' command: Evaluate a Salus expression.
var evalCommand = new Command("eval", "Evaluate a Salus expression and print the result.")
{
    new Argument<string>("expression", "The Salus expression to evaluate.")
};
evalCommand.SetHandler(async (string expression, bool verbose, ILogger<SalusApp> log) =>
{
    if (verbose) log.LogDebug("Verbose output enabled.");
    log.LogInformation($"Evaluating expression: {expression}");
    // TODO: Integrate with SalusEngine to parse, evaluate, and print the result.
    await Task.Delay(100); // Simulate asynchronous work
    Console.WriteLine($"Result: (Simulated output for: {expression})");
    log.LogInformation($"Expression '{expression}' evaluated.");
}, evalCommand.GetInvocationBuilder().GetAction<string, bool, ILogger<SalusApp>>());

// 'script' command: Alias for 'run'.
var scriptCommand = new Command("script", "Load and execute a Salus script file (alias for run).")
{
    new Argument<string>("filePath", "Path to the Salus script file.")
};
scriptCommand.SetHandler(async (string filePath, bool verbose, ILogger<SalusApp> log) =>
{
    if (verbose) log.LogDebug("Verbose output enabled.");
    log.LogInformation($"Loading and running script file: {filePath}");
    // TODO: Delegate to the 'run' command logic or SalusEngine.
    await Task.Delay(100); // Simulate asynchronous work
    log.LogInformation($"Script file '{filePath}' finished successfully.");
}, scriptCommand.GetInvocationBuilder().GetAction<string, bool, ILogger<SalusApp>>());

// Add all commands to the root command.
rootCommand.AddCommand(runCommand);
rootCommand.AddCommand(execCommand);
rootCommand.AddCommand(evalCommand);
rootCommand.AddCommand(scriptCommand);

// Set default handler for when no command is specified (e.g., just 'salus').
// This typically enters interactive mode based on requirements.
rootCommand.SetHandler(async (InvocationContext context) =>
{
    var logFromContext = context.GetRequiredService<ILogger<SalusApp>>();
    var verbose = context.ParseResult.GetValueForOption(rootCommand.Options.OfType<Option<bool>>().First(o => o.Name == "verbose"));
    if (verbose) logFromContext.LogDebug("Verbose output enabled in default handler.");

    // If no command was explicitly given and no other arguments are present, enter interactive mode.
    if (context.ParseResult.Command == rootCommand && context.ParseResult.Tokens.Count == 0)
    {
        logFromContext.LogInformation("Entering Salus interactive mode. Type 'exit' to quit.");
        while (true)
        {
            Console.Write("Salus> ");
            string? input = Console.ReadLine(); // Use nullable string for ReadLine result
            if (string.IsNullOrWhiteSpace(input) || input.Equals("exit", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
            if (verbose) logFromContext.LogDebug($"Interactive input received: '{input}'");
            // TODO: Call SalusEngine.Execute(input) or a CLI service method.
            Console.WriteLine($"Result: (Simulated output for: {input})");
        }
        logFromContext.LogInformation("Exiting interactive mode.");
    }
    else
    {
        // If arguments are provided but no specific command handler matched,
        // System.CommandLine's default behavior will print help.
        // We can add a custom error message if desired before it prints help.
        logFromContext.LogError("Unrecognized command or invalid arguments. Use 'salus --help' for assistance.");
        context.ExitCode = 1; // Indicate error
    }
});

// 3. Execute the application logic (CLI parsing and invocation)
try
{
    // Build the parser with host integration.
    // UseHost allows System.CommandLine handlers to resolve services from the IHost's service provider.
    var parser = new CommandLineBuilder(rootCommand)
        .UseDefaults() // Adds default middleware (help, version, suggesting corrections, etc.)
        .UseHost(_ => host) // Connects System.CommandLine to the IHost for DI.
        .Build();

    // Parse command-line arguments and invoke the appropriate handler.
    // The `InvokeAsync` method returns the exit code of the command.
    int exitCode = await parser.InvokeAsync(args);

    // If the application hosts long-running background services (e.g., for IPC/RPC with plugins),
    // you might need `await host.RunAsync();` here.
    // For a typical CLI tool that runs a command and exits, `InvokeAsync` is sufficient.

    Environment.Exit(exitCode);
}
catch (Exception ex)
{
    logger.LogCritical(ex, "An unhandled exception occurred during application execution.");
    Environment.Exit(1); // Indicate a general critical error
}

// A placeholder class to provide a clear context for ILogger<T> in the DI system.
// This class itself doesn't need to contain all the main logic, but rather serves
// as the logical "application root" for logging purposes.
internal class SalusApp
{
    private readonly ILogger<SalusApp> _logger;

    public SalusApp(ILogger<SalusApp> logger)
    {
        _logger = logger;
        _logger.LogDebug("SalusApp entry point services initialized.");
        // Perform any critical early startup checks or initializations here.
        // For example, checking configuration, initializing module manager placeholders.
        // await _moduleManager.InitializeAsync(); // Placeholder
    }
}