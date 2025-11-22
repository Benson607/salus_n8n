using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;
using System.Net.Http; // For net.http_get

namespace Salus
{
    // Custom Exception Types for error classification
    public class SalusSyntaxError : Exception
    {
        public SalusSyntaxError(string message) : base(message) { }
        public SalusSyntaxError(string message, Exception innerException) : base(message, innerException) { }
    }

    public class SalusRuntimeError : Exception
    {
        public SalusRuntimeError(string message) : base(message) { }
        public SalusRuntimeError(string message, Exception innerException) : base(message, innerException) { }
    }

    public class SalusSecurityError : Exception
    {
        public SalusSecurityError(string message) : base(message) { }
        public SalusSecurityError(string message, Exception innerException) : base(message, innerException) { }
    }

    // --- I. 系統架構與模組設計 ---

    /// <summary>
    /// 錯誤與日誌系統：提供統一格式的錯誤追蹤與日誌輸出，支援加密與簽章防竄改。
    /// </summary>
    public static class ErrorLogger
    {
        private static readonly string LogFilePath = Path.Combine(AppContext.BaseDirectory, "salus.log");
        private static RSAParameters _privateKey; // For signing
        private static RSAParameters _publicKey;  // For verification
        private static bool _initialized = false;

        public static void Initialize()
        {
            if (_initialized) return;

            // In a real application, keys would be loaded securely, not generated on startup.
            // For production, consider using a hardware security module (HSM) or secure key store.
            using (var rsa = RSA.Create())
            {
                _privateKey = rsa.ExportParameters(true);
                _publicKey = rsa.ExportParameters(false);
            }
            _initialized = true;
        }

        public static async Task LogError(Exception ex, string context = "Application", LogLevel level = LogLevel.Error)
        {
            Initialize(); // Ensure keys are initialized

            var timestamp = DateTimeOffset.UtcNow.ToString("o");
            var errorDetails = new StringBuilder();
            errorDetails.AppendLine($"Timestamp: {timestamp}");
            errorDetails.AppendLine($"Level: {level}");
            errorDetails.AppendLine($"Context: {context}");
            errorDetails.AppendLine($"Type: {ex.GetType().Name}");
            errorDetails.AppendLine($"Message: {ex.Message}");
            errorDetails.AppendLine($"StackTrace: {ex.StackTrace}");
            if (ex.InnerException != null)
            {
                errorDetails.AppendLine($"InnerException Type: {ex.InnerException.GetType().Name}");
                errorDetails.AppendLine($"InnerException Message: {ex.InnerException.Message}");
                errorDetails.AppendLine($"InnerException StackTrace: {ex.InnerException.StackTrace}");
            }

            var logEntry = errorDetails.ToString();
            var encryptedLogEntry = EncryptLog(logEntry);
            var signature = SignLog(encryptedLogEntry);

            var fullLogEntry = $"---BEGIN LOG ENTRY---\n{encryptedLogEntry}\n---SIGNATURE---\n{Convert.ToBase64String(signature)}\n---END LOG ENTRY---\n";

            try
            {
                await File.AppendAllTextAsync(LogFilePath, fullLogEntry);
            }
            catch (Exception fileEx)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Failed to write to log file: {fileEx.Message}");
                Console.ResetColor();
            }

            // Also output to console for immediate user feedback (without encryption/signing for readability)
            Console.ForegroundColor = level == LogLevel.Error || level == LogLevel.Security ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.WriteLine($"[{level}] {timestamp} ({context}): {ex.Message}");
            Console.ResetColor();
        }

        private static string EncryptLog(string log)
        {
            // Placeholder for actual encryption logic.
            // For now, base64 encode to simulate "encryption" as it's not plain text.
            // In a real scenario, use AES for bulk data encryption, and RSA to secure the AES key.
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(log));
        }

        private static byte[] SignLog(string encryptedLog)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(_privateKey);
                var data = Encoding.UTF8.GetBytes(encryptedLog);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error,
            Security
        }
    }

    /// <summary>
    /// 安全權限模型：外部命令沙箱化執行，權限控管，日誌安全性，外掛驗證。
    /// </summary>
    public static class SecurityManager
    {
        private static readonly Dictionary<string, List<string>> _permissions = new Dictionary<string, List<string>>(); // user/role -> capabilities
        private static bool _initialized = false;

        public static void Initialize()
        {
            if (_initialized) return;

            // Load permissions from a configuration file or system.
            // This should be loaded securely (e.g., encrypted config).
            // Example:
            _permissions["admin"] = new List<string> { "fs.read", "fs.write", "net.http", "exec.all", "plugin.load", "plugin.load_unsigned" };
            _permissions["user"] = new List<string> { "fs.read", "net.http" };

            // Default permissions for current user
            string currentUser = Environment.UserName;
            if (!_permissions.ContainsKey(currentUser))
            {
                _permissions[currentUser] = _permissions["user"]; // Assign default user permissions
            }
            _initialized = true;
        }

        public static bool HasPermission(string userOrRole, string capability)
        {
            Initialize(); // Ensure permissions are loaded

            if (_permissions.TryGetValue(userOrRole, out var capabilities))
            {
                return capabilities.Contains(capability);
            }
            return false;
        }

        public static bool VerifyDigitalSignature(string filePath, string expectedPublisher)
        {
            // Placeholder for actual digital signature verification
            // This would involve checking the file's authenticode signature, publisher certificate chain, etc.
            // For plugins, this is critical to prevent malicious code execution.
            Console.WriteLine($"[SecurityManager] Verifying digital signature for {filePath} from {expectedPublisher}...");
            
            // Simulate signature verification. In a real scenario, this would involve complex crypto APIs.
            // For demonstration, we'll return true if the file path contains "signed_plugin"
            if (filePath.Contains("signed_plugin"))
            {
                Console.WriteLine("[SecurityManager] Digital signature VERIFIED (simulated).");
                return true;
            }
            Console.WriteLine("[SecurityManager] Digital signature FAILED (simulated).");
            return false;
        }

        public static bool IsSafePath(string path, string userOrRole = null)
        {
            // Implement robust logic to ensure paths are within allowed I/O areas.
            // This is crucial for preventing directory traversal attacks.
            if (string.IsNullOrWhiteSpace(path)) return false;

            var absolutePath = Path.GetFullPath(path);
            var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);

            // Basic check: is the path within the application's base directory or a specifically allowed user directory?
            // This is a simplified check. A full system would involve configurable allowed directories per user/role.
            if (absolutePath.StartsWith(baseDirectory, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Example: Allow user-specific temporary directories if configured
            // if (userOrRole != null && HasPermission(userOrRole, "fs.allow_user_temp") && absolutePath.StartsWith(Path.GetTempPath())) { return true; }

            return false; // Disallow access to paths outside the app's base directory by default
        }
    }

    /// <summary>
    /// 外掛沙箱與通訊介面（IPC/RPC）：確保外掛安全隔離與可控通訊。
    /// This uses an AssemblyLoadContext for isolation. For true sandbox, separate processes with IPC/RPC.
    /// </summary>
    public class PluginSandbox : AssemblyLoadContext
    {
        private AssemblyDependencyResolver _resolver;
        private string _pluginPath;

        public PluginSandbox(string pluginPath) : base(isCollectible: true)
        {
            _pluginPath = pluginPath;
            _resolver = new AssemblyDependencyResolver(pluginPath);
        }

        protected override Assembly Load(AssemblyName assemblyName)
        {
            string assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
            if (assemblyPath != null)
            {
                return LoadFromAssemblyPath(assemblyPath);
            }
            return null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            string libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            if (libraryPath != null)
            {
                return LoadUnmanagedDllFromPath(libraryPath);
            }
            return IntPtr.Zero;
        }

        public T LoadPlugin<T>() where T : class
        {
            if (!File.Exists(_pluginPath))
            {
                throw new FileNotFoundException($"Plugin not found at {_pluginPath}");
            }

            // For true security, this would involve IPC/RPC for communication with the sandboxed plugin.
            // Here, AssemblyLoadContext provides assembly isolation (dependency conflicts, unloading),
            // but not full process-level security isolation (e.g., file system access, network access).
            // A robust sandbox would involve:
            // 1. Loading the plugin in a separate process.
            // 2. Using .NET's `System.AppDomain` (in .NET Framework) or custom host/IPC channels (.NET Core+).
            // 3. Limiting API calls available to the plugin via an IPC proxy.

            var assembly = LoadFromAssemblyPath(_pluginPath);
            var pluginType = assembly.GetTypes().FirstOrDefault(t => typeof(T).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);

            if (pluginType == null)
            {
                throw new InvalidOperationException($"No plugin type implementing {typeof(T).Name} found in {_pluginPath}");
            }

            return (T)Activator.CreateInstance(pluginType);
        }
    }


    /// <summary>
    /// 模組管理器：支援外掛（plugin）與擴充套件載入，具備版本與相依性檢查。
    /// </summary>
    public class ModuleManager
    {
        private readonly string _pluginDirectory = Path.Combine(AppContext.BaseDirectory, "plugins");
        private readonly Dictionary<string, (Version version, ISalusPlugin instance, PluginSandbox sandbox)> _loadedPlugins = new Dictionary<string, (Version, ISalusPlugin, PluginSandbox)>();

        public ModuleManager()
        {
            if (!Directory.Exists(_pluginDirectory))
            {
                Directory.CreateDirectory(_pluginDirectory);
            }
        }

        public async Task LoadPlugins()
        {
            Console.WriteLine("[ModuleManager] Discovering plugins...");
            foreach (var pluginFile in Directory.GetFiles(_pluginDirectory, "*.dll"))
            {
                try
                {
                    await LoadPlugin(pluginFile);
                }
                catch (Exception ex)
                {
                    await ErrorLogger.LogError(ex, $"Plugin Load Failed: {Path.GetFileName(pluginFile)}");
                }
            }
        }

        public async Task LoadPlugin(string pluginPath)
        {
            // Perform basic checks before loading assembly metadata
            if (!File.Exists(pluginPath)) throw new FileNotFoundException($"Plugin not found: {pluginPath}");

            var assemblyName = AssemblyName.GetAssemblyName(pluginPath);
            var pluginName = assemblyName.Name;
            var pluginVersion = assemblyName.Version;

            Console.WriteLine($"[ModuleManager] Attempting to load plugin: {pluginName} v{pluginVersion}");

            // 1. 外掛驗證：需經數位簽章與版本比對後方可載入。
            string currentUser = Environment.UserName;
            if (!SecurityManager.VerifyDigitalSignature(pluginPath, "SalusTeam"))
            {
                if (!SecurityManager.HasPermission(currentUser, "plugin.load_unsigned"))
                {
                    throw new SalusSecurityError($"Plugin '{pluginName}' failed digital signature verification and user lacks permission to load unsigned plugins.");
                }
                else
                {
                    Console.WriteLine($"[ModuleManager] WARNING: Loading unsigned plugin '{pluginName}' as user '{currentUser}' has 'plugin.load_unsigned' permission.");
                }
            }

            // Version check
            if (_loadedPlugins.TryGetValue(pluginName, out var existingPlugin))
            {
                if (existingPlugin.version >= pluginVersion)
                {
                    Console.WriteLine($"[ModuleManager] Plugin {pluginName} v{pluginVersion} is already loaded or a newer/equal version ({existingPlugin.version}) exists. Skipping.");
                    return;
                }
                else
                {
                    Console.WriteLine($"[ModuleManager] Newer version {pluginVersion} of {pluginName} found. Unloading old version {existingPlugin.version}.");
                    existingPlugin.sandbox.Unload(); // Unload the old AssemblyLoadContext
                    _loadedPlugins.Remove(pluginName);
                }
            }

            // 2. Load plugin in a sandbox (AssemblyLoadContext)
            var sandbox = new PluginSandbox(pluginPath);
            var pluginInstance = sandbox.LoadPlugin<ISalusPlugin>();

            _loadedPlugins[pluginName] = (pluginVersion, pluginInstance, sandbox);
            Console.WriteLine($"[ModuleManager] Successfully loaded plugin: {pluginName} v{pluginVersion}");

            await pluginInstance.Initialize(SalusEngine.Instance); // Initialize plugin with access to SalusEngine
        }

        public T GetPlugin<T>(string name) where T : class
        {
            if (_loadedPlugins.TryGetValue(name, out var entry))
            {
                return entry.instance as T;
            }
            return null;
        }

        // Placeholder interface for plugins to adhere to.
        public interface ISalusPlugin
        {
            string Name { get; }
            Version Version { get; }
            Task Initialize(SalusEngine engine);
            // Potentially methods for executing commands, registering built-ins, etc.
        }
    }

    /// <summary>
    /// 核心直譯器 (Salus Engine)：負責語法解析與執行，提供 AST 構建與錯誤追蹤機制。
    /// 內建函式庫、型別系統、非同步執行模型、記憶體管理 (物件池)
    /// </summary>
    public class SalusEngine
    {
        private static SalusEngine _instance;
        public static SalusEngine Instance => _instance ??= new SalusEngine();

        private readonly Dictionary<string, Func<List<object>, Task<object>>> _builtInFunctions = new Dictionary<string, Func<List<object>, Task<object>>>();
        private readonly Stack<Dictionary<string, object>> _scopeStack = new Stack<Dictionary<string, object>>(); // For variable scoping
        private readonly ObjectPool<List<object>> _listObjectPool = new ObjectPool<List<object>>(() => new List<object>(), 100);

        private SalusEngine()
        {
            _scopeStack.Push(new Dictionary<string, object>()); // Global scope
            RegisterBuiltInFunctions();
            Console.WriteLine("[SalusEngine] Initialized.");
        }

        private void RegisterBuiltInFunctions()
        {
            // --- II. Salus 語言設計規格 - 內建函式庫 ---
            // 檔案系統
            _builtInFunctions["fs.read_text"] = async args =>
            {
                if (args.Count != 1 || !(args[0] is string path)) throw new SalusRuntimeError("fs.read_text requires a single string argument (file path).");
                string currentUser = Environment.UserName;
                if (!SecurityManager.HasPermission(currentUser, "fs.read")) throw new SalusSecurityError($"Permission denied for '{currentUser}': fs.read");
                if (!SecurityManager.IsSafePath(path, currentUser)) throw new SalusSecurityError("Access to unsafe path denied.");
                return await File.ReadAllTextAsync(path);
            };
            _builtInFunctions["fs.write_text"] = async args =>
            {
                if (args.Count != 2 || !(args[0] is string path) || !(args[1] is string content)) throw new SalusRuntimeError("fs.write_text requires two string arguments (file path, content).");
                string currentUser = Environment.UserName;
                if (!SecurityManager.HasPermission(currentUser, "fs.write")) throw new SalusSecurityError($"Permission denied for '{currentUser}': fs.write");
                if (!SecurityManager.IsSafePath(path, currentUser)) throw new SalusSecurityError("Access to unsafe path denied.");
                await File.WriteAllTextAsync(path, content);
                return null;
            };

            // 網路
            _builtInFunctions["net.http_get"] = async args =>
            {
                if (args.Count != 1 || !(args[0] is string url)) throw new SalusRuntimeError("net.http_get requires a single string argument (URL).");
                string currentUser = Environment.UserName;
                if (!SecurityManager.HasPermission(currentUser, "net.http")) throw new SalusSecurityError($"Permission denied for '{currentUser}': net.http");
                using var client = new HttpClient();
                return await client.GetStringAsync(url);
            };

            // 字串
            _builtInFunctions["str.length"] = args =>
            {
                if (args.Count != 1 || !(args[0] is string s)) throw new SalusRuntimeError("str.length requires a single string argument.");
                return Task.FromResult<object>(s.Length);
            };

            // 集合
            _builtInFunctions["list.add"] = args =>
            {
                if (args.Count != 2 || !(args[0] is List<object> list)) throw new SalusRuntimeError("list.add requires a list and an item.");
                list.Add(args[1]);
                return Task.FromResult<object>(null);
            };

            // 時間
            _builtInFunctions["time.now"] = args => Task.FromResult<object>(DateTime.Now.ToString());

            // 系統命令操作
            _builtInFunctions["sys.exec"] = async args =>
            {
                if (args.Count < 1 || !(args[0] is string command)) throw new SalusRuntimeError("sys.exec requires at least one string argument (command).");
                string currentUser = Environment.UserName;
                if (!SecurityManager.HasPermission(currentUser, "exec.cmd")) throw new SalusSecurityError($"Permission denied for '{currentUser}': exec.cmd");
                var commandArgs = args.Skip(1).Select(a => a?.ToString()).ToList();
                return await ExternalCommandBridge.ExecuteCommandSafe(command, commandArgs);
            };

            // Basic print function
            _builtInFunctions["print"] = args =>
            {
                Console.WriteLine(string.Join(" ", args));
                return Task.FromResult<object>(null);
            };
        }

        // Placeholder for AST Node classes (II.1 語法結構)
        public abstract class AstNode { }
        public class LiteralNode : AstNode { public object Value { get; set; } }
        public class VariableAccessNode : AstNode { public string Name { get; set; } }
        public class VariableAssignNode : AstNode { public string Name { get; set; } public AstNode Value { get; set; } }
        public class CallNode : AstNode { public AstNode Function { get; set; } public List<AstNode> Arguments { get; set; } }
        public class BlockNode : AstNode { public List<AstNode> Statements { get; set; } }
        // ... more node types for conditions, loops, module import, pipeline operation etc.

        /// <summary>
        /// 負責語法解析（Lexer -> Parser -> AST） (II.1 語法結構)
        /// </summary>
        public AstNode Parse(string code)
        {
            // This is a minimal, illustrative parser. A real parser would use a lexer (tokenizer)
            // and a proper parsing algorithm (e.g., recursive descent, LL(k)) to build a robust AST.
            Console.WriteLine($"[SalusEngine] Parsing code: {code.Substring(0, Math.Min(code.Length, 80))}...");

            code = code.Trim();

            if (code.StartsWith("print("))
            {
                var content = code.Substring("print(".Length, code.Length - "print(".Length - 1).Trim();
                if (content.StartsWith("\"") && content.EndsWith("\"") || content.StartsWith("'") && content.EndsWith("'"))
                {
                    content = content.Trim('\'', '\"');
                }
                return new CallNode { Function = new VariableAccessNode { Name = "print" }, Arguments = new List<AstNode> { new LiteralNode { Value = content } } };
            }
            else if (code.StartsWith("var "))
            {
                // Simple variable declaration: var x = 10; or var msg = "hello";
                var parts = code.Substring("var ".Length).Split('=', 2);
                if (parts.Length == 2)
                {
                    var varName = parts[0].Trim();
                    var varValue = parts[1].Trim();
                    
                    AstNode valueNode;
                    if (int.TryParse(varValue, out int intVal)) valueNode = new LiteralNode { Value = intVal };
                    else if (double.TryParse(varValue, out double doubleVal)) valueNode = new LiteralNode { Value = doubleVal };
                    else if (varValue.StartsWith("\"") && varValue.EndsWith("\"") || varValue.StartsWith("'") && varValue.EndsWith("'"))
                    {
                        valueNode = new LiteralNode { Value = varValue.Trim('\'', '\"') };
                    }
                    else // Could be a variable access or function call
                    {
                        // Simplified: Treat as a variable access for now
                        valueNode = new VariableAccessNode { Name = varValue };
                    }
                    return new VariableAssignNode { Name = varName, Value = valueNode };
                }
            }
            else if (code.Contains("(") && code.Contains(")")) // Heuristic for a function call
            {
                var funcNameEnd = code.IndexOf('(');
                if (funcNameEnd > 0)
                {
                    var funcName = code.Substring(0, funcNameEnd).Trim();
                    var argsString = code.Substring(funcNameEnd + 1, code.Length - funcNameEnd - 2).Trim();
                    var argNodes = new List<AstNode>();
                    
                    // Simple argument splitting, needs robust parsing for nested calls/strings
                    foreach (var argPart in argsString.Split(','))
                    {
                        var trimmedArg = argPart.Trim();
                        if (trimmedArg.StartsWith("\"") && trimmedArg.EndsWith("\"") || trimmedArg.StartsWith("'") && trimmedArg.EndsWith("'"))
                        {
                            argNodes.Add(new LiteralNode { Value = trimmedArg.Trim('\'', '\"') });
                        }
                        else if (int.TryParse(trimmedArg, out int intVal))
                        {
                            argNodes.Add(new LiteralNode { Value = intVal });
                        }
                        else if (double.TryParse(trimmedArg, out double doubleVal))
                        {
                            argNodes.Add(new LiteralNode { Value = doubleVal });
                        }
                        else if (!string.IsNullOrEmpty(trimmedArg))
                        {
                            argNodes.Add(new VariableAccessNode { Name = trimmedArg }); // Assume it's a variable or another function call
                        }
                    }
                    return new CallNode { Function = new VariableAccessNode { Name = funcName }, Arguments = argNodes };
                }
            }
            else if (!string.IsNullOrEmpty(code))
            {
                // Assume it's a variable access or simple literal if no other pattern matches
                if (int.TryParse(code, out int intVal)) return new LiteralNode { Value = intVal };
                if (double.TryParse(code, out double doubleVal)) return new LiteralNode { Value = doubleVal };
                return new VariableAccessNode { Name = code };
            }

            throw new SalusSyntaxError($"Invalid syntax: '{code}'");
        }

        /// <summary>
        /// 執行 AST (II.6 直譯與執行模型)
        /// </summary>
        public async Task<object> Execute(AstNode ast)
        {
            // Placeholder for AST traversal and execution.
            // This is where type checking (II.2) would happen before or during execution.
            // And async/await handling (II.3) is central for language constructs.

            if (ast is BlockNode block)
            {
                object lastResult = null;
                foreach (var statement in block.Statements)
                {
                    lastResult = await Execute(statement);
                }
                return lastResult;
            }
            else if (ast is CallNode callNode)
            {
                string funcName = null;
                if (callNode.Function is VariableAccessNode funcVarNode)
                {
                    funcName = funcVarNode.Name;
                }
                else
                {
                    throw new SalusRuntimeError($"Cannot call non-function object: {callNode.Function.GetType().Name}");
                }

                if (_builtInFunctions.TryGetValue(funcName, out var func))
                {
                    var args = _listObjectPool.Get();
                    try
                    {
                        foreach (var argNode in callNode.Arguments)
                        {
                            args.Add(await Evaluate(argNode));
                        }
                        return await func(args);
                    }
                    finally
                    {
                        args.Clear();
                        _listObjectPool.Return(args);
                    }
                }
                else
                {
                    throw new SalusRuntimeError($"Function '{funcName}' not found.");
                }
            }
            else if (ast is VariableAssignNode varAssignment)
            {
                // Evaluate the right-hand side of the assignment
                var value = await Evaluate(varAssignment.Value);
                _scopeStack.Peek()[varAssignment.Name] = value;
                Console.WriteLine($"[SalusEngine] Assigned '{varAssignment.Name}' = '{value}'"); // For debugging
                return null; // Assignments typically don't return a value
            }
            else if (ast is LiteralNode literalNode)
            {
                return literalNode.Value;
            }
            else if (ast is VariableAccessNode varAccessNode)
            {
                foreach (var scope in _scopeStack)
                {
                    if (scope.TryGetValue(varAccessNode.Name, out var value))
                    {
                        return value;
                    }
                }
                throw new SalusRuntimeError($"Variable '{varAccessNode.Name}' not found.");
            }

            throw new SalusRuntimeError($"Unsupported AST node type or expression: {ast.GetType().Name}");
        }

        private async Task<object> Evaluate(AstNode node)
        {
            // This method handles evaluating an AST node to its runtime value.
            // It recursively calls Execute for nodes that represent operations (like CallNode).
            if (node is LiteralNode literal) return literal.Value;
            if (node is VariableAccessNode varNode)
            {
                foreach (var scope in _scopeStack)
                {
                    if (scope.TryGetValue(varNode.Name, out var value))
                    {
                        return value;
                    }
                }
                throw new SalusRuntimeError($"Variable '{varNode.Name}' not found.");
            }
            // For complex expressions or nested function calls, we execute them
            return await Execute(node);
        }

        // --- II. Salus 語言設計規格 - 記憶體管理 (物件池) ---
        public class ObjectPool<T> where T : class
        {
            private readonly Queue<T> _objects;
            private readonly Func<T> _objectGenerator;
            private readonly int _maxSize;

            public ObjectPool(Func<T> objectGenerator, int maxSize)
            {
                _objectGenerator = objectGenerator ?? throw new ArgumentNullException(nameof(objectGenerator));
                _maxSize = maxSize;
                _objects = new Queue<T>();
            }

            public T Get()
            {
                lock (_objects)
                {
                    if (_objects.Count > 0)
                    {
                        return _objects.Dequeue();
                    }
                    return _objectGenerator();
                }
            }

            public void Return(T item)
            {
                lock (_objects)
                {
                    if (_objects.Count < _maxSize)
                    {
                        // Reset item state if necessary before returning to pool
                        // E.g., for List<object>, clear it.
                        if (item is ICollection<object> collection)
                        {
                            collection.Clear();
                        }
                        _objects.Enqueue(item);
                    }
                    // If pool is full, let GC collect the item naturally
                }
            }
        }
    }

    /// <summary>
    /// 外部指令橋接層：與系統命令及應用程式整合，支援 API 呼叫與安全權限控制。
    /// </summary>
    public static class ExternalCommandBridge
    {
        public static async Task<string> ExecuteCommandSafe(string command, List<string> args)
        {
            string currentUser = Environment.UserName;
            if (!SecurityManager.HasPermission(currentUser, "exec.full") && !SecurityManager.HasPermission(currentUser, "exec.cmd"))
            {
                throw new SalusSecurityError($"Permission denied for '{currentUser}': Direct system command execution.");
            }

            Console.WriteLine($"[ExternalCommandBridge] Executing: {command} {string.Join(" ", args)}");

            // --- IV. 安全與權限模型 - 外部命令沙箱化執行 ---
            // This is a minimal process execution. For true sandboxing:
            // 1. Run in a separate, isolated process with limited user rights (e.g., a dedicated low-privilege user).
            // 2. Use a restricted environment (e.g., cgroups on Linux, AppContainer/Job Objects on Windows).
            // 3. Monitor and filter process I/O, network access, etc.
            // 4. Time limits and resource limits.
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = command,
                    Arguments = string.Join(" ", args.Select(arg => EscapeArgument(arg))),
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false, // Must be false for redirection
                    CreateNoWindow = true,
                    // Environment variables could be cleaned/restricted here (e.g., PATH, HOME)
                    // WorkingDirectory could be restricted here (e.g., to a temporary, sandboxed location)
                };

                using (var process = System.Diagnostics.Process.Start(startInfo))
                {
                    if (process == null) throw new SalusRuntimeError($"Failed to start process: {command}. Ensure command exists and is in PATH.");

                    var outputTask = process.StandardOutput.ReadToEndAsync();
                    var errorTask = process.StandardError.ReadToEndAsync();

                    // Timeout for external commands to prevent hanging (configurable)
                    var timeoutTask = Task.Delay(TimeSpan.FromSeconds(30)); // 30 second timeout
                    var completedTask = await Task.WhenAny(process.WaitForExitAsync(), timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        try { process.Kill(); } catch { /* ignore if process already exited */ }
                        throw new SalusRuntimeError($"Command '{command}' timed out after 30 seconds.");
                    }

                    // Ensure all output streams are read before checking ExitCode
                    await Task.WhenAll(outputTask, errorTask);

                    var stdout = outputTask.Result;
                    var stderr = errorTask.Result;

                    if (process.ExitCode != 0)
                    {
                        var errorMsg = $"Command '{command}' exited with code {process.ExitCode}. Stderr: {stderr.Trim()}";
                        await ErrorLogger.LogError(new Exception(errorMsg), "ExternalCommand");
                        throw new SalusRuntimeError(errorMsg);
                    }

                    return stdout.Trim();
                }
            }
            catch (System.ComponentModel.Win32Exception w32ex) when (w32ex.NativeErrorCode == 2) // File not found
            {
                throw new SalusRuntimeError($"Command '{command}' not found. Check your PATH or command spelling.", w32ex);
            }
            catch (Exception ex)
            {
                await ErrorLogger.LogError(ex, "ExternalCommandBridge Execution");
                throw new SalusRuntimeError($"Error executing external command '{command}': {ex.Message}", ex);
            }
        }

        private static string EscapeArgument(string arg)
        {
            // Simple escaping for arguments. More robust escaping is needed for various shells/platforms (Windows vs Linux/macOS).
            // This example uses double quotes, which works for many cases on both Windows and Unix-like systems.
            if (string.IsNullOrEmpty(arg)) return "\"\"";
            
            // If the argument contains spaces, quotes, or special shell characters, enclose it in double quotes.
            // Within double quotes, escape existing double quotes.
            if (arg.Any(c => char.IsWhiteSpace(c) || c == '"' || c == '\\' || c == '$' || c == '`' || c == '&' || c == '|' || c == ';' || c == '<' || c == '>' || c == '(' || c == ')' || c == '*'))
            {
                return $"\"{arg.Replace("\"", "\\\"")}\"";
            }
            return arg;
        }
    }


    /// <summary>
    /// Salus CLI 介面模組
    /// </summary>
    public class SalusCli
    {
        private readonly SalusEngine _engine;
        private readonly ModuleManager _moduleManager;
        private readonly string _historyFile = Path.Combine(AppContext.BaseDirectory, ".salus_history");
        private readonly List<string> _commandHistory = new List<string>();

        // For I18n/L10n
        private CultureInfo _currentCulture = CultureInfo.CurrentCulture;
        private Dictionary<string, string> _translations = new Dictionary<string, string>();

        public SalusCli(SalusEngine engine, ModuleManager moduleManager)
        {
            _engine = engine;
            _moduleManager = moduleManager;
            LoadHistory();
            LoadLocalization(CultureInfo.CurrentCulture.Name); // Default localization based on system
        }

        private void LoadLocalization(string cultureName)
        {
            try
            {
                _currentCulture = new CultureInfo(cultureName);
            }
            catch (CultureNotFoundException)
            {
                Console.WriteLine($"[WARNING] Culture '{cultureName}' not found. Falling back to invariant culture.");
                _currentCulture = CultureInfo.InvariantCulture;
            }
            
            _translations.Clear();
            // In a full i18n system, these would be loaded from .resx files or similar.
            // For now, hardcode a few common translations.
            if (_currentCulture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase)) // Covers zh-TW, zh-CN, etc.
            {
                _translations["help_message"] = "Salus 命令列介面。輸入 'exit' 離開，'help' 獲取幫助。";
                _translations["prompt"] = "salus>";
                _translations["error_prefix"] = "錯誤：";
                _translations["result_prefix"] = "結果：";
                _translations["command_not_found"] = "未知的指令或語法。";
                _translations["diag_message"] = "運行診斷模式...";
                _translations["report_message"] = "生成系統報告...";
                _translations["language_set"] = "語言已設為";
                _translations["script_file_not_found"] = "腳本文件未找到：";
            }
            else // Default to English
            {
                _translations["help_message"] = "Salus CLI. Type 'exit' to quit, 'help' for assistance.";
                _translations["prompt"] = "salus>";
                _translations["error_prefix"] = "Error:";
                _translations["result_prefix"] = "Result:";
                _translations["command_not_found"] = "Unknown command or syntax.";
                _translations["diag_message"] = "Running diagnostic mode...";
                _translations["report_message"] = "Generating system report...";
                _translations["language_set"] = "Language set to";
                _translations["script_file_not_found"] = "Script file not found:";
            }
            Console.OutputEncoding = Encoding.UTF8; // Ensure proper display of localized characters
        }

        private string GetLocalizedText(string key)
        {
            return _translations.TryGetValue(key, out var text) ? text : key;
        }

        private void LoadHistory()
        {
            if (File.Exists(_historyFile))
            {
                try
                {
                    _commandHistory.AddRange(File.ReadAllLines(_historyFile));
                }
                catch (Exception ex)
                {
                    ErrorLogger.LogError(ex, "CLI History Load", ErrorLogger.LogLevel.Warning).Wait();
                }
            }
        }

        private void SaveHistory()
        {
            try
            {
                File.WriteAllLines(_historyFile, _commandHistory);
            }
            catch (Exception ex)
            {
                ErrorLogger.LogError(ex, "CLI History Save", ErrorLogger.LogLevel.Warning).Wait();
            }
        }

        /// <summary>
        /// Main CLI loop for interactive mode.
        /// </summary>
        public async Task RunInteractiveMode()
        {
            Console.WriteLine($"Salus CLI v{Assembly.GetExecutingAssembly().GetName().Version}");
            Console.WriteLine(GetLocalizedText("help_message"));

            // Example of setting theme (Requires Spectre.Console or similar)
            // AnsiConsole.MarkupLine("[bold blue]Salus[/] [green]Engine[/] initialized!");

            while (true)
            {
                string input = await PromptInput(GetLocalizedText("prompt")); // Auto-completion, history managed by PromptInput

                if (string.IsNullOrWhiteSpace(input)) continue;

                _commandHistory.Add(input);

                try
                {
                    if (input.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    else if (input.Equals("help", StringComparison.OrdinalIgnoreCase) || input.Equals("--help", StringComparison.OrdinalIgnoreCase))
                    {
                        DisplayHelp();
                    }
                    else if (input.StartsWith("salus diag", StringComparison.OrdinalIgnoreCase))
                    {
                        await RunDiagnosticMode(input);
                    }
                    else if (input.StartsWith("salus report", StringComparison.OrdinalIgnoreCase))
                    {
                        await RunReportMode(input);
                    }
                    else if (input.StartsWith("set lang ", StringComparison.OrdinalIgnoreCase))
                    {
                        var langCode = input.Substring("set lang ".Length).Trim();
                        LoadLocalization(langCode);
                        Console.WriteLine($"{GetLocalizedText("language_set")} {_currentCulture.Name}");
                    }
                    else
                    {
                        // --- III. CLI 互動層設計 - 指令結構 (run, exec, eval, script) ---
                        // Simplified handling for now. A real implementation would parse the command.
                        if (input.StartsWith("run ", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleRunCommand(input.Substring(4).Trim());
                        }
                        else if (input.StartsWith("eval ", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleEvalCommand(input.Substring(5).Trim());
                        }
                        else if (input.StartsWith("exec ", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleExecCommand(input.Substring(5).Trim());
                        }
                        else if (input.StartsWith("script ", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleScriptCommand(input.Substring(7).Trim());
                        }
                        else
                        {
                            // Default to eval if no specific command given
                            await HandleEvalCommand(input);
                        }
                    }
                }
                catch (SalusSyntaxError ex)
                {
                    await ErrorLogger.LogError(ex, "CLI-Syntax");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{GetLocalizedText("error_prefix")} {ex.Message}");
                    Console.ResetColor();
                }
                catch (SalusRuntimeError ex)
                {
                    await ErrorLogger.LogError(ex, "CLI-Runtime");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{GetLocalizedText("error_prefix")} {ex.Message}");
                    Console.ResetColor();
                }
                catch (SalusSecurityError ex)
                {
                    await ErrorLogger.LogError(ex, "CLI-Security", ErrorLogger.LogLevel.Security);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{GetLocalizedText("error_prefix")} {ex.Message}");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    await ErrorLogger.LogError(ex, "CLI-Unhandled");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{GetLocalizedText("error_prefix")} An unexpected error occurred: {ex.Message}");
                    Console.ResetColor();
                }
            }
            SaveHistory();
        }

        private async Task<string> PromptInput(string prompt)
        {
            // This is where a ReadLine-like library (e.g., System.CommandLine.Rendering, ConsoleTables, etc.)
            // would be integrated for rich console features:
            // - History: _commandHistory (already managed, but ReadLine would provide interactive browsing)
            // - Auto-completion: dynamically provide suggestions (e.g., built-in functions, variable names, file paths)
            // - Syntax highlighting: As user types, for real-time feedback
            // - Error live detection: basic syntax check on-the-fly
            Console.Write(prompt);
            // Simulate rich input:
            return await Task.Run(() => Console.ReadLine()); // Simplified: just read line
        }

        private async Task HandleEvalCommand(string code)
        {
            Console.WriteLine($"[CLI] Evaluating: {code}");
            var ast = _engine.Parse(code);
            var result = await _engine.Execute(ast);
            if (result != null)
            {
                // UX: Output format (table, JSON, plain text)
                // Using Spectre.Console for rich output formats would be ideal here.
                Console.WriteLine($"{GetLocalizedText("result_prefix")} {result}");
            }
        }

        private async Task HandleRunCommand(string scriptPath)
        {
            Console.WriteLine($"[CLI] Running script: {scriptPath}");
            if (!File.Exists(scriptPath)) throw new SalusRuntimeError($"{GetLocalizedText("script_file_not_found")} {scriptPath}");
            var scriptContent = await File.ReadAllTextAsync(scriptPath);
            await HandleEvalCommand(scriptContent); // Simplified: Just eval the entire script
        }

        private async Task HandleExecCommand(string commandLine)
        {
            Console.WriteLine($"[CLI] Executing external command: {commandLine}");
            var parts = commandLine.Split(' ', 2);
            var command = parts[0];
            var args = parts.Length > 1 ? parts[1].Split(' ').ToList() : new List<string>();
            var result = await ExternalCommandBridge.ExecuteCommandSafe(command, args);
            Console.WriteLine($"Command Output:\n{result}");
        }

        private async Task HandleScriptCommand(string scriptPath)
        {
            // Similar to run, but might imply more formal script execution with environment setup
            await HandleRunCommand(scriptPath);
        }


        private void DisplayHelp()
        {
            Console.WriteLine(GetLocalizedText("help_message"));
            Console.WriteLine("Available commands:");
            Console.WriteLine("  eval <code_string>     - Evaluate a Salus code snippet.");
            Console.WriteLine("  run <file_path>        - Run a Salus script file.");
            Console.WriteLine("  exec <command> [args]  - Execute a system command.");
            Console.WriteLine("  script <file_path>     - Alias for 'run'.");
            Console.WriteLine("  salus diag [options]   - Run diagnostic tools.");
            Console.WriteLine("  salus report [options] - Generate system report.");
            Console.WriteLine("  set lang <culture_code>- Set display language (e.g., en-US, zh-TW).");
            Console.WriteLine("  exit                   - Exit the CLI.");
            Console.WriteLine("  --help                 - Display this help message.");
            // Add more help as per VII.1 (salus --help)
        }

        private async Task RunDiagnosticMode(string input)
        {
            Console.WriteLine(GetLocalizedText("diag_message"));
            // Example diagnostics:
            Console.WriteLine($"  .NET Runtime: {Environment.Version}");
            Console.WriteLine($"  OS: {Environment.OSVersion} ({Environment.OSVersion.Platform})");
            Console.WriteLine($"  Processor Count: {Environment.ProcessorCount}");
            Console.WriteLine($"  Current Directory: {Environment.CurrentDirectory}");
            Console.WriteLine($"  Salus Log Path: {Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "salus.log"))}");
            Console.WriteLine($"  Plugins Directory: {Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "plugins"))}");
            Console.WriteLine($"  Loaded Plugins: {_moduleManager._loadedPlugins.Count}");
            foreach (var entry in _moduleManager._loadedPlugins)
            {
                Console.WriteLine($"    - {entry.Key} v{entry.Value.version}");
            }
            // Add more detailed diagnostics: loaded modules, config, permissions, network checks
            await Task.CompletedTask;
        }

        private async Task RunReportMode(string input)
        {
            Console.WriteLine(GetLocalizedText("report_message"));
            // This would gather detailed system info, Salus config, logs, etc.
            // and format it, possibly encrypting/signing before saving.
            var reportContent = new StringBuilder();
            reportContent.AppendLine("Salus System Report:");
            reportContent.AppendLine($"- Version: {Assembly.GetExecutingAssembly().GetName().Version}");
            reportContent.AppendLine($"- Runtime: .NET {Environment.Version}");
            reportContent.AppendLine($"- OS: {Environment.OSVersion}");
            reportContent.AppendLine($"- User: {Environment.UserName}");
            reportContent.AppendLine($"- Current Culture: {_currentCulture.Name}");
            reportContent.AppendLine("--- Loaded Plugins ---");
            foreach (var entry in _moduleManager._loadedPlugins)
            {
                reportContent.AppendLine($"- {entry.Key} v{entry.Value.version}");
            }
            // Add more details from diagnostics, configuration, plugin list, etc.
            reportContent.AppendLine("--- END REPORT ---");

            var reportFilePath = Path.Combine(AppContext.BaseDirectory, $"salus_report_{DateTime.Now:yyyyMMddHHmmss}.txt");
            try
            {
                await File.WriteAllTextAsync(reportFilePath, reportContent.ToString());
                Console.WriteLine($"Report saved to: {reportFilePath}");
            }
            catch (Exception ex)
            {
                await ErrorLogger.LogError(ex, "Report Generation", ErrorLogger.LogLevel.Error);
                Console.WriteLine($"{GetLocalizedText("error_prefix")} Failed to save report: {ex.Message}");
            }
            await Task.CompletedTask;
        }
    }


    // Main entry point of the application
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // --- V. 開發與執行環境規範 ---
            // Target .NET 8 (implicit by project file, ensure .csproj targets net8.0)
            // Self-contained publish (configured via project file for deployment)
            // Cross-platform (handled by .NET itself)

            // --- I. 系統架構與模組設計 - 初始化各模組 ---
            // --- IV. 安全與權限模型 - 初始化安全管理 ---
            SecurityManager.Initialize();
            ErrorLogger.Initialize(); // Initialize logger keys
            await ErrorLogger.LogError(new Exception("Salus application started."), "Startup", ErrorLogger.LogLevel.Info); // Example log

            var moduleManager = new ModuleManager();
            var salusEngine = SalusEngine.Instance; // Singleton
            var salusCli = new SalusCli(salusEngine, moduleManager);

            // Load plugins asynchronously at startup
            await moduleManager.LoadPlugins();


            // --- III. CLI 互動層設計 - 指令結構 (run, exec, eval, script modes) ---
            if (args.Length == 0)
            {
                // Interactive mode
                await salusCli.RunInteractiveMode();
            }
            else
            {
                // Non-interactive / Scripting mode
                // Simple argument parsing for modes. A more robust solution would use a CLI parser library like System.CommandLine.
                try
                {
                    string command = args[0].ToLowerInvariant();
                    // Join remaining args for commands like 'eval' or 'exec' which take a single string or multiple args
                    string fullArgumentString = string.Join(" ", args.Skip(1));
                    
                    switch (command)
                    {
                        case "run":
                        case "script":
                            await salusCli.HandleRunCommand(fullArgumentString);
                            break;
                        case "eval":
                            await salusCli.HandleEvalCommand(fullArgumentString);
                            break;
                        case "exec":
                            // For exec, the argument is the command, and subsequent args are its arguments
                            await salusCli.HandleExecCommand(fullArgumentString);
                            break;
                        case "diag":
                            await salusCli.RunDiagnosticMode(string.Join(" ", args));
                            break;
                        case "report":
                            await salusCli.RunReportMode(string.Join(" ", args));
                            break;
                        case "--help":
                        case "-h":
                            salusCli.DisplayHelp();
                            break;
                        default:
                            // If no explicit command, treat the whole argument string as an eval expression
                            await salusCli.HandleEvalCommand(string.Join(" ", args));
                            break;
                    }
                }
                catch (Exception ex)
                {
                    await ErrorLogger.LogError(ex, "CLI-NonInteractive");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: {ex.Message}");
                    Console.ResetColor();
                    Environment.ExitCode = 1; // Indicate error
                }
            }

            await ErrorLogger.LogError(new Exception("Salus application exited."), "Shutdown", ErrorLogger.LogLevel.Info);
        }
    }
}