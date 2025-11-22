using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using System.Collections.Concurrent;
using System.Runtime.Loader; // For AssemblyLoadContext

namespace Salus
{
    // 1. 核心直譯器（Salus Engine）
    public class SalusEngine
    {
        private Lexer _lexer;
        private Parser _parser;
        private Interpreter _interpreter;
        private ErrorTracker _errorTracker;
        private ModuleManager _moduleManager;
        private PermissionManager _permissionManager;
        private SalusLogger _logger;

        public SalusEngine(SalusLogger logger, PermissionManager permissionManager)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _permissionManager = permissionManager ?? throw new ArgumentNullException(nameof(permissionManager));
            _lexer = new Lexer(logger);
            _parser = new Parser(logger);
            _errorTracker = new ErrorTracker(logger);
            _interpreter = new Interpreter(_errorTracker, _logger, _permissionManager);
            _moduleManager = new ModuleManager(_logger);

            // Initialize built-in functions
            BuiltInFunctions.Register(_interpreter.GlobalScope, _permissionManager);
        }

        public async Task<SalusValue> Execute(string code, string mode = "eval", string sourceName = "<stdin>")
        {
            try
            {
                // Lexing
                var tokens = _lexer.Tokenize(code, sourceName);
                if (_errorTracker.HasErrors)
                {
                    _errorTracker.LogErrors();
                    return SalusValue.Error(new SyntaxError("Lexing failed."));
                }

                // Parsing and AST Construction
                var ast = _parser.Parse(tokens);
                if (_errorTracker.HasErrors)
                {
                    _errorTracker.LogErrors();
                    return SalusValue.Error(new SyntaxError("Parsing failed."));
                }

                // Semantic Analysis (Type checking, etc.) - Placeholder
                // _semanticAnalyzer.Analyze(ast);
                // if (_errorTracker.HasErrors) { _errorTracker.LogErrors(); return SalusValue.Error(new TypeError("Semantic analysis failed.")); }

                // Execution
                var result = await _interpreter.Evaluate(ast);
                return result;
            }
            catch (SalusException ex)
            {
                _errorTracker.ReportError(ex);
                return SalusValue.Error(ex);
            }
            catch (Exception ex)
            {
                var runtimeError = new RuntimeError("Unhandled internal error during execution.", inner: ex);
                _errorTracker.ReportError(runtimeError);
                _logger.LogCritical($"Unhandled internal error: {ex}", ex);
                return SalusValue.Error(runtimeError);
            }
            finally
            {
                _errorTracker.ClearErrors();
            }
        }

        public async Task LoadModule(string modulePath)
        {
            // This would load Salus source code module or a .NET plugin.
            // For .NET plugins, ModuleManager.LoadPlugin is used.
            // For Salus scripts, we'd read and execute them here.
            _logger.LogInfo($"Attempting to load Salus module script: {modulePath}");
            if (!File.Exists(modulePath))
            {
                _logger.LogError($"Module script not found: {modulePath}");
                throw new RuntimeError($"Module script not found: {modulePath}");
            }
            if (!_permissionManager.CheckPermission(PermissionType.FileSystemRead, modulePath))
            {
                throw new SecurityError($"Permission denied to read module script: {modulePath}");
            }
            string scriptContent = await File.ReadAllTextAsync(modulePath);
            await Execute(scriptContent, "module", modulePath); // Execute as a module
        }

        // Placeholder for AST nodes
        public abstract class AstNode
        {
            public SourceLocation Location { get; set; }
            public virtual IEnumerable<AstNode> Children => Enumerable.Empty<AstNode>();
            public abstract T Accept<T>(IAstVisitor<T> visitor);
            public override string ToString() => GetType().Name;
        }

        public interface IAstVisitor<T>
        {
            T Visit(ProgramNode node);
            T Visit(ExpressionStatementNode node);
            T Visit(IdentifierNode node);
            T Visit(LiteralNode node);
            T Visit(BinaryExpressionNode node);
            T Visit(CallExpressionNode node);
            T Visit(VariableDeclarationNode node);
            T Visit(IfStatementNode node);
            T Visit(WhileStatementNode node);
            T Visit(BlockStatementNode node);
            T Visit(FunctionDeclarationNode node);
            T Visit(ReturnStatementNode node);
        }

        // Example AST nodes
        public class ProgramNode : AstNode
        {
            public List<AstNode> Statements { get; set; } = new List<AstNode>();
            public override IEnumerable<AstNode> Children => Statements;
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class ExpressionStatementNode : AstNode
        {
            public AstNode Expression { get; set; }
            public override IEnumerable<AstNode> Children => new[] { Expression };
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class IdentifierNode : AstNode
        {
            public string Name { get; set; }
            public IdentifierNode(string name, SourceLocation location = null) { Name = name; Location = location; }
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class LiteralNode : AstNode
        {
            public SalusValue Value { get; set; }
            public LiteralNode(SalusValue value, SourceLocation location = null) { Value = value; Location = location; }
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class BinaryExpressionNode : AstNode
        {
            public AstNode Left { get; set; }
            public Token Operator { get; set; }
            public AstNode Right { get; set; }
            public BinaryExpressionNode(AstNode left, Token op, AstNode right, SourceLocation location = null) { Left = left; Operator = op; Right = right; Location = location; }
            public override IEnumerable<AstNode> Children => new[] { Left, Right };
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class CallExpressionNode : AstNode
        {
            public AstNode Callee { get; set; }
            public List<AstNode> Arguments { get; set; } = new List<AstNode>();
            public CallExpressionNode(AstNode callee, List<AstNode> args, SourceLocation location = null) { Callee = callee; Arguments = args; Location = location; }
            public override IEnumerable<AstNode> Children => Arguments.Prepend(Callee);
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class VariableDeclarationNode : AstNode
        {
            public IdentifierNode Name { get; set; }
            public AstNode Initializer { get; set; }
            public SalusType DeclaredType { get; set; } // For static typing
            public VariableDeclarationNode(IdentifierNode name, AstNode initializer, SalusType declaredType = null, SourceLocation location = null) { Name = name; Initializer = initializer; DeclaredType = declaredType; Location = location; }
            public override IEnumerable<AstNode> Children => Initializer != null ? new[] { Name, Initializer } : new[] { Name };
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class IfStatementNode : AstNode
        {
            public AstNode Condition { get; set; }
            public AstNode Consequence { get; set; }
            public AstNode Alternative { get; set; } // Optional 'else' branch
            public IfStatementNode(AstNode condition, AstNode consequence, AstNode alternative = null, SourceLocation location = null) { Condition = condition; Consequence = consequence; Alternative = alternative; Location = location; }
            public override IEnumerable<AstNode> Children => Alternative != null ? new[] { Condition, Consequence, Alternative } : new[] { Condition, Consequence };
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class WhileStatementNode : AstNode
        {
            public AstNode Condition { get; set; }
            public AstNode Body { get; set; }
            public WhileStatementNode(AstNode condition, AstNode body, SourceLocation location = null) { Condition = condition; Body = body; Location = location; }
            public override IEnumerable<AstNode> Children => new[] { Condition, Body };
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class BlockStatementNode : AstNode
        {
            public List<AstNode> Statements { get; set; } = new List<AstNode>();
            public override IEnumerable<AstNode> Children => Statements;
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class FunctionDeclarationNode : AstNode
        {
            public IdentifierNode Name { get; set; }
            public List<IdentifierNode> Parameters { get; set; } = new List<IdentifierNode>();
            public BlockStatementNode Body { get; set; }
            public SalusType ReturnType { get; set; } // For static typing
            public FunctionDeclarationNode(IdentifierNode name, List<IdentifierNode> parameters, BlockStatementNode body, SalusType returnType = null, SourceLocation location = null) { Name = name; Parameters = parameters; Body = body; ReturnType = returnType; Location = location; }
            public override IEnumerable<AstNode> Children => Parameters.Cast<AstNode>().Append(Body);
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }

        public class ReturnStatementNode : AstNode
        {
            public AstNode Value { get; set; }
            public ReturnStatementNode(AstNode value, SourceLocation location = null) { Value = value; Location = location; }
            public override IEnumerable<AstNode> Children => Value != null ? new[] { Value } : Enumerable.Empty<AstNode>();
            public override T Accept<T>(IAstVisitor<T> visitor) => visitor.Visit(this);
        }


        // Placeholder for Lexer, Parser, Interpreter
        public class Lexer
        {
            private SalusLogger _logger;
            private ErrorTracker _errorTracker; // Lexer should also report errors
            private string _sourceName;

            public Lexer(SalusLogger logger, ErrorTracker errorTracker = null)
            {
                _logger = logger;
                _errorTracker = errorTracker ?? new ErrorTracker(logger);
            }

            public List<Token> Tokenize(string code, string sourceName = "<stdin>")
            {
                _logger.LogDebug($"Lexing code from {sourceName}...");
                _sourceName = sourceName;
                var tokens = new List<Token>();
                int current = 0;
                int line = 1;
                int column = 1;

                while (current < code.Length)
                {
                    char c = code[current];
                    SourceLocation location = new SourceLocation(line, column, _sourceName);

                    if (char.IsWhiteSpace(c))
                    {
                        if (c == '\n') { line++; column = 1; }
                        else { column++; }
                        current++;
                        continue;
                    }

                    if (char.IsLetter(c) || c == '_')
                    {
                        StringBuilder sb = new StringBuilder();
                        while (current < code.Length && (char.IsLetterOrDigit(code[current]) || code[current] == '_'))
                        {
                            sb.Append(code[current]);
                            current++;
                            column++;
                        }
                        string value = sb.ToString();
                        TokenType type = Keywords.ContainsKey(value) ? Keywords[value] : TokenType.Identifier;
                        tokens.Add(new Token(type, value, location));
                        continue;
                    }

                    if (char.IsDigit(c))
                    {
                        StringBuilder sb = new StringBuilder();
                        while (current < code.Length && char.IsDigit(code[current]))
                        {
                            sb.Append(code[current]);
                            current++;
                            column++;
                        }
                        if (current < code.Length && code[current] == '.')
                        {
                            sb.Append(code[current]);
                            current++;
                            column++;
                            while (current < code.Length && char.IsDigit(code[current]))
                            {
                                sb.Append(code[current]);
                                current++;
                                column++;
                            }
                        }
                        tokens.Add(new Token(TokenType.Number, sb.ToString(), location));
                        continue;
                    }

                    if (c == '"')
                    {
                        StringBuilder sb = new StringBuilder();
                        current++; // Consume opening quote
                        column++;
                        while (current < code.Length && code[current] != '"')
                        {
                            sb.Append(code[current]);
                            current++;
                            column++;
                        }
                        if (current >= code.Length)
                        {
                            _errorTracker.ReportError(new SyntaxError("Unterminated string literal.", location));
                            break;
                        }
                        current++; // Consume closing quote
                        column++;
                        tokens.Add(new Token(TokenType.String, sb.ToString(), location));
                        continue;
                    }

                    // Simple operators/separators
                    switch (c)
                    {
                        case '+': tokens.Add(new Token(TokenType.Operator, "+", location)); break;
                        case '-': tokens.Add(new Token(TokenType.Operator, "-", location)); break;
                        case '*': tokens.Add(new Token(TokenType.Operator, "*", location)); break;
                        case '/': tokens.Add(new Token(TokenType.Operator, "/", location)); break;
                        case '=': tokens.Add(new Token(TokenType.Operator, "=", location)); break;
                        case '(': tokens.Add(new Token(TokenType.Separator, "(", location)); break;
                        case ')': tokens.Add(new Token(TokenType.Separator, ")", location)); break;
                        case '{': tokens.Add(new Token(TokenType.Separator, "{", location)); break;
                        case '}': tokens.Add(new Token(TokenType.Separator, "}", location)); break;
                        case '[': tokens.Add(new Token(TokenType.Separator, "[", location)); break;
                        case ']': tokens.Add(new Token(TokenType.Separator, "]", location)); break;
                        case ',': tokens.Add(new Token(TokenType.Separator, ",", location)); break;
                        case ';': tokens.Add(new Token(TokenType.Separator, ";", location)); break;
                        case '.': tokens.Add(new Token(TokenType.Separator, ".", location)); break;
                        default:
                            _errorTracker.ReportError(new SyntaxError($"Unexpected character: '{c}'", location));
                            break;
                    }
                    current++;
                    column++;
                }

                tokens.Add(new Token(TokenType.Eof, "", new SourceLocation(line, column, _sourceName)));
                return tokens;
            }

            private static readonly Dictionary<string, TokenType> Keywords = new Dictionary<string, TokenType>
            {
                {"var", TokenType.Keyword},
                {"func", TokenType.Keyword},
                {"if", TokenType.Keyword},
                {"else", TokenType.Keyword},
                {"while", TokenType.Keyword},
                {"return", TokenType.Keyword},
                {"true", TokenType.Keyword},
                {"false", TokenType.Keyword},
                {"null", TokenType.Keyword},
                {"async", TokenType.Keyword},
                {"await", TokenType.Keyword},
            };
        }

        public class Parser
        {
            private SalusLogger _logger;
            private ErrorTracker _errorTracker;
            private List<Token> _tokens;
            private int _current;

            public Parser(SalusLogger logger, ErrorTracker errorTracker = null)
            {
                _logger = logger;
                _errorTracker = errorTracker ?? new ErrorTracker(logger);
            }

            public AstNode Parse(List<Token> tokens)
            {
                _logger.LogDebug("Parsing tokens...");
                _tokens = tokens;
                _current = 0;
                var program = new ProgramNode { Location = Peek().Location };

                while (!IsAtEnd())
                {
                    program.Statements.Add(ParseStatement());
                }

                return program;
            }

            private AstNode ParseStatement()
            {
                if (Match(TokenType.Keyword, "var")) return ParseVariableDeclaration();
                if (Match(TokenType.Keyword, "func")) return ParseFunctionDeclaration();
                if (Match(TokenType.Keyword, "if")) return ParseIfStatement();
                if (Match(TokenType.Keyword, "while")) return ParseWhileStatement();
                if (Match(TokenType.Keyword, "return")) return ParseReturnStatement();
                if (Match(TokenType.Separator, "{")) return ParseBlockStatement();
                return ParseExpressionStatement();
            }

            private VariableDeclarationNode ParseVariableDeclaration()
            {
                Token varToken = Previous();
                IdentifierNode name = ExpectIdentifier("Expected variable name after 'var'.");
                AstNode initializer = null;
                SalusType declaredType = null; // Placeholder for type annotation

                if (Match(TokenType.Operator, "="))
                {
                    initializer = ParseExpression();
                }
                Expect(TokenType.Separator, ";", "Expected ';' after variable declaration.");
                return new VariableDeclarationNode(name, initializer, declaredType, varToken.Location);
            }

            private FunctionDeclarationNode ParseFunctionDeclaration()
            {
                Token funcToken = Previous();
                IdentifierNode name = ExpectIdentifier("Expected function name after 'func'.");
                Expect(TokenType.Separator, "(", "Expected '(' after function name.");
                List<IdentifierNode> parameters = new List<IdentifierNode>();
                if (!Check(TokenType.Separator, ")"))
                {
                    do
                    {
                        parameters.Add(ExpectIdentifier("Expected parameter name."));
                    } while (Match(TokenType.Separator, ","));
                }
                Expect(TokenType.Separator, ")", "Expected ')' after parameters.");

                SalusType returnType = null; // Placeholder for return type annotation

                BlockStatementNode body = ExpectBlockStatement("Expected '{' for function body.");
                return new FunctionDeclarationNode(name, parameters, body, returnType, funcToken.Location);
            }

            private IfStatementNode ParseIfStatement()
            {
                Token ifToken = Previous();
                Expect(TokenType.Separator, "(", "Expected '(' after 'if'.");
                AstNode condition = ParseExpression();
                Expect(TokenType.Separator, ")", "Expected ')' after if condition.");
                AstNode consequence = ParseStatement();
                AstNode alternative = null;
                if (Match(TokenType.Keyword, "else"))
                {
                    alternative = ParseStatement();
                }
                return new IfStatementNode(condition, consequence, alternative, ifToken.Location);
            }

            private WhileStatementNode ParseWhileStatement()
            {
                Token whileToken = Previous();
                Expect(TokenType.Separator, "(", "Expected '(' after 'while'.");
                AstNode condition = ParseExpression();
                Expect(TokenType.Separator, ")", "Expected ')' after while condition.");
                AstNode body = ParseStatement();
                return new WhileStatementNode(condition, body, whileToken.Location);
            }

            private ReturnStatementNode ParseReturnStatement()
            {
                Token returnToken = Previous();
                AstNode value = null;
                if (!Check(TokenType.Separator, ";"))
                {
                    value = ParseExpression();
                }
                Expect(TokenType.Separator, ";", "Expected ';' after return value.");
                return new ReturnStatementNode(value, returnToken.Location);
            }

            private BlockStatementNode ParseBlockStatement()
            {
                Token openBrace = Previous(); // Consume '{'
                BlockStatementNode block = new BlockStatementNode { Location = openBrace.Location };
                while (!Check(TokenType.Separator, "}") && !IsAtEnd())
                {
                    block.Statements.Add(ParseStatement());
                }
                Expect(TokenType.Separator, "}", "Expected '}' after block.");
                return block;
            }

            private ExpressionStatementNode ParseExpressionStatement()
            {
                AstNode expr = ParseExpression();
                Expect(TokenType.Separator, ";", "Expected ';' after expression.");
                return new ExpressionStatementNode { Expression = expr, Location = expr.Location };
            }

            private AstNode ParseExpression()
            {
                return ParseAssignment();
            }

            private AstNode ParseAssignment()
            {
                AstNode expr = ParseEquality();

                if (Match(TokenType.Operator, "="))
                {
                    Token equals = Previous();
                    AstNode value = ParseAssignment(); // Right-associativity for assignment

                    if (expr is IdentifierNode identifier)
                    {
                        return new BinaryExpressionNode(identifier, equals, value, equals.Location); // Represent assignment as a binary op for now
                    }
                    _errorTracker.ReportError(new SyntaxError("Invalid assignment target.", equals.Location));
                }
                return expr;
            }

            private AstNode ParseEquality()
            {
                AstNode expr = ParseComparison();
                while (Match(TokenType.Operator, "==", "!="))
                {
                    Token op = Previous();
                    AstNode right = ParseComparison();
                    expr = new BinaryExpressionNode(expr, op, right, op.Location);
                }
                return expr;
            }

            private AstNode ParseComparison()
            {
                AstNode expr = ParseTerm();
                while (Match(TokenType.Operator, ">", ">=", "<", "<="))
                {
                    Token op = Previous();
                    AstNode right = ParseTerm();
                    expr = new BinaryExpressionNode(expr, op, right, op.Location);
                }
                return expr;
            }

            private AstNode ParseTerm()
            {
                AstNode expr = ParseFactor();
                while (Match(TokenType.Operator, "+", "-"))
                {
                    Token op = Previous();
                    AstNode right = ParseFactor();
                    expr = new BinaryExpressionNode(expr, op, right, op.Location);
                }
                return expr;
            }

            private AstNode ParseFactor()
            {
                AstNode expr = ParseUnary();
                while (Match(TokenType.Operator, "*", "/"))
                {
                    Token op = Previous();
                    AstNode right = ParseUnary();
                    expr = new BinaryExpressionNode(expr, op, right, op.Location);
                }
                return expr;
            }

            private AstNode ParseUnary()
            {
                if (Match(TokenType.Operator, "!", "-"))
                {
                    Token op = Previous();
                    AstNode right = ParseUnary();
                    return new BinaryExpressionNode(null, op, right, op.Location); // Unary represented as binary with null left
                }
                return ParseCall();
            }

            private AstNode ParseCall()
            {
                AstNode expr = ParsePrimary();

                while (true)
                {
                    if (Match(TokenType.Separator, "("))
                    {
                        expr = FinishCall(expr);
                    }
                    // TODO: Add support for member access (e.g., object.property)
                    else
                    {
                        break;
                    }
                }
                return expr;
            }

            private AstNode FinishCall(AstNode callee)
            {
                List<AstNode> arguments = new List<AstNode>();
                if (!Check(TokenType.Separator, ")"))
                {
                    do
                    {
                        arguments.Add(ParseExpression());
                    } while (Match(TokenType.Separator, ","));
                }
                Token paren = Expect(TokenType.Separator, ")", "Expected ')' after arguments.");
                return new CallExpressionNode(callee, arguments, paren.Location);
            }

            private AstNode ParsePrimary()
            {
                if (Match(TokenType.Keyword, "false")) return new LiteralNode(SalusValue.False, Previous().Location);
                if (Match(TokenType.Keyword, "true")) return new LiteralNode(SalusValue.True, Previous().Location);
                if (Match(TokenType.Keyword, "null")) return new LiteralNode(SalusValue.Null, Previous().Location);

                if (Match(TokenType.Number)) return new LiteralNode(SalusValue.FromObject(double.Parse(Previous().Value)), Previous().Location);
                if (Match(TokenType.String)) return new LiteralNode(SalusValue.FromObject(Previous().Value), Previous().Location);
                if (Match(TokenType.Identifier)) return new IdentifierNode(Previous().Value, Previous().Location);

                if (Match(TokenType.Separator, "("))
                {
                    AstNode expr = ParseExpression();
                    Expect(TokenType.Separator, ")", "Expected ')' after expression.");
                    return expr;
                }

                _errorTracker.ReportError(new SyntaxError("Expected expression.", Peek().Location));
                throw new SyntaxError("Expected expression.", Peek().Location); // To break out of parsing
            }

            private bool Match(TokenType type, params string[] values)
            {
                if (Check(type, values))
                {
                    Advance();
                    return true;
                }
                return false;
            }

            private bool Match(TokenType type)
            {
                if (Check(type))
                {
                    Advance();
                    return true;
                }
                return false;
            }

            private bool Check(TokenType type, params string[] values)
            {
                if (IsAtEnd()) return false;
                if (Peek().Type != type) return false;
                if (values.Length == 0) return true;
                return values.Contains(Peek().Value);
            }

            private bool Check(TokenType type)
            {
                if (IsAtEnd()) return false;
                return Peek().Type == type;
            }

            private Token Advance()
            {
                if (!IsAtEnd()) _current++;
                return Previous();
            }

            private bool IsAtEnd() => Peek().Type == TokenType.Eof;

            private Token Peek() => _tokens[_current];
            private Token Previous() => _tokens[_current - 1];

            private Token Expect(TokenType type, string value, string message)
            {
                if (Check(type, value)) return Advance();
                _errorTracker.ReportError(new SyntaxError(message, Peek().Location));
                throw new SyntaxError(message, Peek().Location);
            }

            private IdentifierNode ExpectIdentifier(string message)
            {
                if (Check(TokenType.Identifier))
                {
                    Token identifierToken = Advance();
                    return new IdentifierNode(identifierToken.Value, identifierToken.Location);
                }
                _errorTracker.ReportError(new SyntaxError(message, Peek().Location));
                throw new SyntaxError(message, Peek().Location);
            }

            private BlockStatementNode ExpectBlockStatement(string message)
            {
                if (Check(TokenType.Separator, "{"))
                {
                    return ParseBlockStatement();
                }
                _errorTracker.ReportError(new SyntaxError(message, Peek().Location));
                throw new SyntaxError(message, Peek().Location);
            }
        }

        public class Interpreter : IAstVisitor<Task<SalusValue>>
        {
            private ErrorTracker _errorTracker;
            private SalusLogger _logger;
            private PermissionManager _permissionManager;
            public Scope GlobalScope { get; private set; }
            private AsyncTaskScheduler _taskScheduler; // For async/await

            public Interpreter(ErrorTracker errorTracker, SalusLogger logger, PermissionManager permissionManager)
            {
                _errorTracker = errorTracker;
                _logger = logger;
                _permissionManager = permissionManager;
                GlobalScope = new Scope(null);
                _taskScheduler = new AsyncTaskScheduler(_logger);
            }

            public async Task<SalusValue> Evaluate(AstNode ast)
            {
                _logger.LogDebug("Interpreting AST...");
                try
                {
                    return await ast.Accept(this);
                }
                catch (SalusException ex)
                {
                    throw ex; // Re-throw Salus specific exceptions
                }
                catch (Exception ex)
                {
                    throw new RuntimeError($"Internal interpreter error: {ex.Message}", ast.Location, ex);
                }
            }

            public async Task<SalusValue> Visit(ProgramNode node)
            {
                SalusValue lastResult = SalusValue.Null;
                foreach (var statement in node.Statements)
                {
                    lastResult = await statement.Accept(this);
                    if (lastResult.Type == SalusType.Return)
                    {
                        return lastResult.Value as SalusValue; // Unwrap return value
                    }
                }
                return lastResult;
            }

            public async Task<SalusValue> Visit(ExpressionStatementNode node)
            {
                return await node.Expression.Accept(this);
            }

            public Task<SalusValue> Visit(IdentifierNode node)
            {
                return Task.FromResult(GlobalScope.Resolve(node.Name, node.Location));
            }

            public Task<SalusValue> Visit(LiteralNode node)
            {
                return Task.FromResult(node.Value);
            }

            public async Task<SalusValue> Visit(BinaryExpressionNode node)
            {
                // Simple assignment for now
                if (node.Operator.Value == "=")
                {
                    if (!(node.Left is IdentifierNode identifier))
                    {
                        _errorTracker.ReportError(new RuntimeError("Invalid assignment target.", node.Left.Location));
                        return SalusValue.Error(new RuntimeError("Invalid assignment target.", node.Left.Location));
                    }
                    SalusValue value = await node.Right.Accept(this);
                    GlobalScope.Assign(identifier.Name, value, node.Location);
                    return value;
                }

                SalusValue left = node.Left != null ? await node.Left.Accept(this) : SalusValue.Null; // For unary ops
                SalusValue right = await node.Right.Accept(this);

                if (left.Type == SalusType.Error) return left;
                if (right.Type == SalusType.Error) return right;

                // Basic arithmetic/comparison for numbers
                if (left.Type == SalusType.Number && right.Type == SalusType.Number)
                {
                    double lVal = (double)left.Value;
                    double rVal = (double)right.Value;
                    return node.Operator.Value switch
                    {
                        "+" => SalusValue.FromObject(lVal + rVal),
                        "-" => SalusValue.FromObject(lVal - rVal),
                        "*" => SalusValue.FromObject(lVal * rVal),
                        "/" => SalusValue.FromObject(lVal / rVal),
                        "==" => SalusValue.FromObject(lVal == rVal),
                        "!=" => SalusValue.FromObject(lVal != rVal),
                        ">" => SalusValue.FromObject(lVal > rVal),
                        ">=" => SalusValue.FromObject(lVal >= rVal),
                        "<" => SalusValue.FromObject(lVal < rVal),
                        "<=" => SalusValue.FromObject(lVal <= rVal),
                        // Unary minus
                        _ when node.Left == null && node.Operator.Value == "-" => SalusValue.FromObject(-rVal),
                        _ => throw new RuntimeError($"Unsupported operator for numbers: {node.Operator.Value}", node.Operator.Location)
                    };
                }
                // Unary Not
                if (node.Left == null && node.Operator.Value == "!")
                {
                    return SalusValue.FromObject(!right.IsTruthy());
                }
                // String concatenation
                if (node.Operator.Value == "+" && (left.Type == SalusType.String || right.Type == SalusType.String))
                {
                    return SalusValue.FromObject(left.ToString() + right.ToString());
                }
                // Equality/Inequality for other types (reference equality for objects, value equality for primitives)
                if (node.Operator.Value == "==") return SalusValue.FromObject(left.Equals(right));
                if (node.Operator.Value == "!=") return SalusValue.FromObject(!left.Equals(right));

                _errorTracker.ReportError(new TypeError($"Unsupported operand types for operator '{node.Operator.Value}': {left.Type}, {right.Type}", node.Operator.Location));
                return SalusValue.Error(new TypeError($"Unsupported operand types for operator '{node.Operator.Value}': {left.Type}, {right.Type}", node.Operator.Location));
            }

            public async Task<SalusValue> Visit(CallExpressionNode node)
            {
                SalusValue callee = await node.Callee.Accept(this);
                if (callee.Type == SalusType.Error) return callee;

                if (!(callee.Value is SalusCallable callable))
                {
                    _errorTracker.ReportError(new TypeError($"Cannot call non-callable type: {callee.Type}", node.Callee.Location));
                    return SalusValue.Error(new TypeError($"Cannot call non-callable type: {callee.Type}", node.Callee.Location));
                }

                List<SalusValue> arguments = new List<SalusValue>();
                foreach (var argNode in node.Arguments)
                {
                    arguments.Add(await argNode.Accept(this));
                    if (arguments.Last().Type == SalusType.Error) return arguments.Last();
                }

                return await callable.Call(arguments, _permissionManager);
            }

            public Task<SalusValue> Visit(VariableDeclarationNode node)
            {
                SalusValue value = node.Initializer != null ? node.Initializer.Accept(this).Result : SalusValue.Null; // Await if initializer is async
                GlobalScope.Define(node.Name.Name, value, node.Name.Location);
                return Task.FromResult(value);
            }

            public async Task<SalusValue> Visit(IfStatementNode node)
            {
                SalusValue conditionResult = await node.Condition.Accept(this);
                if (conditionResult.Type == SalusType.Error) return conditionResult;

                if (conditionResult.IsTruthy())
                {
                    return await node.Consequence.Accept(this);
                }
                else if (node.Alternative != null)
                {
                    return await node.Alternative.Accept(this);
                }
                return SalusValue.Null;
            }

            public async Task<SalusValue> Visit(WhileStatementNode node)
            {
                SalusValue lastResult = SalusValue.Null;
                while ((await node.Condition.Accept(this)).IsTruthy())
                {
                    lastResult = await node.Body.Accept(this);
                    if (lastResult.Type == SalusType.Return)
                    {
                        return lastResult; // Propagate return from loop body
                    }
                }
                return lastResult;
            }

            public async Task<SalusValue> Visit(BlockStatementNode node)
            {
                // Blocks create new scopes
                Scope previousScope = GlobalScope;
                GlobalScope = new Scope(previousScope);
                try
                {
                    SalusValue result = SalusValue.Null;
                    foreach (var statement in node.Statements)
                    {
                        result = await statement.Accept(this);
                        if (result.Type == SalusType.Return)
                        {
                            return result; // Propagate return from block
                        }
                    }
                    return result;
                }
                finally
                {
                    GlobalScope = previousScope; // Restore previous scope
                }
            }

            public Task<SalusValue> Visit(FunctionDeclarationNode node)
            {
                var func = new SalusFunction(node, GlobalScope, this);
                GlobalScope.Define(node.Name.Name, SalusValue.FromObject(func), node.Name.Location);
                return Task.FromResult(SalusValue.Null);
            }

            public Task<SalusValue> Visit(ReturnStatementNode node)
            {
                SalusValue returnValue = node.Value != null ? node.Value.Accept(this).Result : SalusValue.Null;
                return Task.FromResult(SalusValue.Return(returnValue)); // Wrap in a special return value to signal function exit
            }
        }

        // Salus Language Design related classes

        // 2.2 型別系統: 支援靜態與動態混合推論、Nullable 與型別檢查。
        public class SalusType
        {
            public string Name { get; }
            public bool IsNullable { get; }
            public SalusType(string name, bool isNullable = false) { Name = name; IsNullable = isNullable; }

            public static SalusType Any = new SalusType("any");
            public static SalusType String = new SalusType("string");
            public static SalusType Number = new SalusType("number");
            public static SalusType Bool = new SalusType("bool");
            public static SalusType Null = new SalusType("null", true);
            public static SalusType Error = new SalusType("error");
            public static SalusType Return = new SalusType("return"); // Special type for interpreter flow control
            public static SalusType Function = new SalusType("function");
            public static SalusType Object = new SalusType("object");
            // ... other types

            public bool IsAssignableTo(SalusType targetType)
            {
                if (targetType == SalusType.Any) return true;
                if (this == targetType) return true;
                if (targetType.IsNullable && this == SalusType.Null) return true;
                if (!targetType.IsNullable && this.IsNullable) return false;

                // More complex type checking logic here (e.g., interface, inheritance, implicit conversions)
                return false;
            }

            public override bool Equals(object obj) => obj is SalusType other && Name == other.Name && IsNullable == other.IsNullable;
            public override int GetHashCode() => HashCode.Combine(Name, IsNullable);
            public override string ToString() => IsNullable ? $"{Name}?" : Name;
        }

        public class SalusValue
        {
            public SalusType Type { get; }
            public object Value { get; }

            private SalusValue(SalusType type, object value) { Type = type; Value = value; }

            public static SalusValue FromObject(object obj)
            {
                if (obj == null) return SalusValue.Null;
                if (obj is SalusValue sv) return sv; // Already a SalusValue
                if (obj is string s) return new SalusValue(SalusType.String, s);
                if (obj is int i) return new SalusValue(SalusType.Number, (double)i);
                if (obj is double d) return new SalusValue(SalusType.Number, d);
                if (obj is bool b) return new SalusValue(SalusType.Bool, b);
                if (obj is SalusException se) return new SalusValue(SalusType.Error, se);
                if (obj is SalusFunction sf) return new SalusValue(SalusType.Function, sf);
                if (obj is SalusCallable sc) return new SalusValue(SalusType.Function, sc); // Built-in functions are callable
                // Add more conversions for other types
                return new SalusValue(SalusType.Object, obj); // Default to 'object' for unhandled types
            }

            public static SalusValue Null => new SalusValue(SalusType.Null, null);
            public static SalusValue True => new SalusValue(SalusType.Bool, true);
            public static SalusValue False => new SalusValue(SalusType.Bool, false);
            public static SalusValue Error(SalusException ex) => new SalusValue(SalusType.Error, ex);
            public static SalusValue Return(SalusValue value) => new SalusValue(SalusType.Return, value);

            public override string ToString() => Value?.ToString() ?? "null";

            public bool IsTruthy()
            {
                if (Type == SalusType.Bool) return (bool)Value;
                if (Type == SalusType.Null) return false;
                if (Type == SalusType.Number) return (double)Value != 0;
                if (Type == SalusType.String) return !string.IsNullOrEmpty((string)Value);
                if (Type == SalusType.Error) return false; // Errors are falsy
                return true; // Objects, functions etc. are truthy
            }

            public override bool Equals(object obj)
            {
                if (obj is SalusValue other)
                {
                    if (Type != other.Type) return false;
                    if (Type == SalusType.Null) return true; // null == null
                    return Value.Equals(other.Value);
                }
                return false;
            }

            public override int GetHashCode() => HashCode.Combine(Type, Value);
        }

        public class Scope
        {
            private readonly Scope _parent;
            private readonly Dictionary<string, SalusValue> _variables = new Dictionary<string, SalusValue>();

            public Scope(Scope parent) => _parent = parent;

            public void Define(string name, SalusValue value, SourceLocation location = null)
            {
                if (_variables.ContainsKey(name))
                {
                    throw new RuntimeError($"Variable '{name}' already defined in this scope.", location);
                }
                _variables.Add(name, value);
            }

            public void Assign(string name, SalusValue value, SourceLocation location = null)
            {
                if (_variables.ContainsKey(name))
                {
                    _variables[name] = value;
                    return;
                }
                if (_parent != null)
                {
                    _parent.Assign(name, value, location);
                    return;
                }
                throw new RuntimeError($"Undefined variable '{name}'.", location);
            }

            public SalusValue Resolve(string name, SourceLocation location = null)
            {
                if (_variables.TryGetValue(name, out var value))
                {
                    return value;
                }
                if (_parent != null)
                {
                    return _parent.Resolve(name, location);
                }
                throw new RuntimeError($"Undefined variable '{name}'.", location);
            }
        }

        public delegate Task<SalusValue> SalusFunctionDelegate(List<SalusValue> args, Scope currentScope, Interpreter interpreter, PermissionManager permissionManager);

        public class SalusCallable
        {
            private readonly SalusFunctionDelegate _func;

            public SalusCallable(SalusFunctionDelegate func)
            {
                _func = func;
            }

            public Task<SalusValue> Call(List<SalusValue> args, PermissionManager permissionManager = null)
            {
                // For built-in functions, the current scope and interpreter context might not be directly relevant
                // unless they need to interact with user-defined variables/functions.
                // For now, pass null for scope/interpreter for simple built-ins.
                return _func(args, null, null, permissionManager);
            }
        }

        public class SalusFunction : SalusCallable
        {
            private readonly FunctionDeclarationNode _declaration;
            private readonly Scope _closure; // Scope where the function was defined
            private readonly Interpreter _interpreter;

            public SalusFunction(FunctionDeclarationNode declaration, Scope closure, Interpreter interpreter)
                : base(null) // Base constructor isn't used for user-defined functions
            {
                _declaration = declaration;
                _closure = closure;
                _interpreter = interpreter;
            }

            public new async Task<SalusValue> Call(List<SalusValue> arguments, PermissionManager permissionManager = null)
            {
                Scope functionScope = new Scope(_closure); // Create new scope inheriting from closure

                // Bind arguments to parameters
                if (arguments.Count != _declaration.Parameters.Count)
                {
                    throw new RuntimeError($"Function '{_declaration.Name.Name}' expected {_declaration.Parameters.Count} arguments but got {arguments.Count}.", _declaration.Location);
                }

                for (int i = 0; i < _declaration.Parameters.Count; i++)
                {
                    functionScope.Define(_declaration.Parameters[i].Name, arguments[i], _declaration.Parameters[i].Location);
                }

                Scope previousScope = _interpreter.GlobalScope;
                _interpreter.GlobalScope = functionScope; // Set interpreter's scope to function scope
                try
                {
                    SalusValue result = await _declaration.Body.Accept(_interpreter);
                    if (result.Type == SalusType.Return)
                    {
                        return result.Value as SalusValue; // Unwrap the returned value
                    }
                    return SalusValue.Null; // Implicit return null
                }
                catch (SalusException ex)
                {
                    throw; // Re-throw Salus exceptions
                }
                finally
                {
                    _interpreter.GlobalScope = previousScope; // Restore previous scope
                }
            }
        }


        // 2.3 非同步執行模型：支援 async/await，具備任務調度與事件循環。
        public class AsyncTaskScheduler : IDisposable
        {
            private SalusLogger _logger;
            private readonly ConcurrentQueue<Func<Task>> _taskQueue = new ConcurrentQueue<Func<Task>>();
            private readonly System.Threading.Timer _eventLoopTimer;
            private const int EventLoopIntervalMs = 10; // Process tasks every 10ms
            private readonly object _processingLock = new object();
            private bool _isDisposed = false;

            public AsyncTaskScheduler(SalusLogger logger)
            {
                _logger = logger;
                _eventLoopTimer = new System.Threading.Timer(async _ => await ProcessTasks(), null, TimeSpan.Zero, TimeSpan.FromMilliseconds(EventLoopIntervalMs));
                _logger.LogInfo("AsyncTaskScheduler started.");
            }

            public void ScheduleTask(Func<Task> taskProducer)
            {
                if (_isDisposed)
                {
                    _logger.LogWarn("Attempted to schedule task on a disposed scheduler.");
                    return;
                }
                _taskQueue.Enqueue(taskProducer);
                _logger.LogDebug("Task scheduled.");
            }

            private async Task ProcessTasks()
            {
                if (!Monitor.TryEnter(_processingLock)) return; // Ensure only one thread processes at a time
                try
                {
                    if (_isDisposed) return;
                    while (_taskQueue.TryDequeue(out var taskProducer))
                    {
                        try
                        {
                            await taskProducer();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error in scheduled async task: {ex.Message}", ex);
                        }
                    }
                }
                finally
                {
                    Monitor.Exit(_processingLock);
                }
            }

            public async Task RunEventLoopUntilEmpty()
            {
                // For scenarios where we need to wait for all scheduled tasks to complete
                // Note: This is a simple wait, more robust solution might involve TaskCompletionSource
                int consecutiveEmptyChecks = 0;
                while (!_isDisposed && (_taskQueue.IsEmpty && consecutiveEmptyChecks < 5 || !_taskQueue.IsEmpty))
                {
                    if (_taskQueue.IsEmpty)
                    {
                        consecutiveEmptyChecks++;
                    }
                    else
                    {
                        consecutiveEmptyChecks = 0;
                    }
                    await Task.Delay(EventLoopIntervalMs);
                }
                _logger.LogInfo("AsyncTaskScheduler event loop drained.");
            }

            public void Dispose()
            {
                if (!_isDisposed)
                {
                    _isDisposed = true;
                    _eventLoopTimer?.Dispose();
                    _logger.LogInfo("AsyncTaskScheduler disposed.");
                }
            }
        }


        // 2.4 錯誤分級：SyntaxError、RuntimeError、SecurityError 等級區分。
        public abstract class SalusException : Exception
        {
            public SourceLocation Location { get; }
            public SalusException(string message, SourceLocation location = null, Exception inner = null)
                : base(message, inner)
            {
                Location = location;
            }

            public override string ToString()
            {
                return $"[{GetType().Name}] {Message} {(Location != null ? $" at {Location}" : "")}{(InnerException != null ? $"\n  Inner: {InnerException.Message}" : "")}";
            }
        }

        public class SyntaxError : SalusException
        {
            public SyntaxError(string message, SourceLocation location = null, Exception inner = null) : base(message, location, inner) { }
        }

        public class RuntimeError : SalusException
        {
            public RuntimeError(string message, SourceLocation location = null, Exception inner = null) : base(message, location, inner) { }
        }

        public class SecurityError : SalusException
        {
            public SecurityError(string message, SourceLocation location = null, Exception inner = null) : base(message, location, inner) { }
        }

        public class TypeError : RuntimeError
        {
            public TypeError(string message, SourceLocation location = null, Exception inner = null) : base(message, location, inner) { }
        }

        public class SourceLocation
        {
            public int Line { get; }
            public int Column { get; }
            public string SourceName { get; }
            public SourceLocation(int line, int column, string sourceName = "<unknown>") { Line = line; Column = column; SourceName = sourceName; }
            public override string ToString() => $"{SourceName}:L{Line},C{Column}";
        }

        // 2.5 內建函式庫：檔案系統、網路、字串、集合、時間與系統命令操作。
        public static class BuiltInFunctions
        {
            public static void Register(Scope scope, PermissionManager permissionManager)
            {
                // Example: print function
                scope.Define("print", SalusValue.FromObject(new SalusCallable(async (args, currentScope, interpreter, permManager) =>
                {
                    Console.WriteLine(string.Join(" ", args.Select(a => a.ToString())));
                    await Task.Yield(); // Make it async-friendly
                    return SalusValue.Null;
                })));

                // Example: file read function (with security check)
                scope.Define("readFile", SalusValue.FromObject(new SalusCallable(async (args, currentScope, interpreter, permManager) =>
                {
                    if (args.Count != 1 || args[0].Type != SalusType.String)
                        throw new RuntimeError("readFile expects one string argument.");

                    string path = args[0].Value.ToString();
                    if (!permManager.CheckPermission(PermissionType.FileSystemRead, path))
                        throw new SecurityError($"Permission denied to read file: {path}");

                    try
                    {
                        return SalusValue.FromObject(await File.ReadAllTextAsync(path));
                    }
                    catch (IOException ex)
                    {
                        throw new RuntimeError($"Failed to read file '{path}': {ex.Message}", inner: ex);
                    }
                })));

                // Example: sleep function (async)
                scope.Define("sleep", SalusValue.FromObject(new SalusCallable(async (args, currentScope, interpreter, permManager) =>
                {
                    if (args.Count != 1 || args[0].Type != SalusType.Number)
                        throw new RuntimeError("sleep expects one number argument (milliseconds).");
                    int milliseconds = (int)(double)args[0].Value;
                    await Task.Delay(milliseconds);
                    return SalusValue.Null;
                })));

                // TODO: Add more built-in functions for network, string, collection, time, system commands
            }
        }

        // 2.7 記憶體管理：採物件池與 .NET GC 混合策略以提升效能。
        public static class ObjectPool<T> where T : class, new()
        {
            private static readonly ConcurrentBag<T> _objects = new ConcurrentBag<T>();
            private const int MaxPoolSize = 1000;

            public static T Get()
            {
                if (_objects.TryTake(out T item))
                {
                    return item;
                }
                return new T();
            }

            public static void Return(T item)
            {
                if (_objects.Count < MaxPoolSize)
                {
                    _objects.Add(item);
                }
            }
        }

        // 3. 模組管理器：支援外掛（plugin）與擴充套件載入，具備版本與相依性檢查。
        // 7. 外掛沙箱與通訊介面（IPC/RPC）：確保外掛安全隔離與可控通訊。
        public class ModuleManager
        {
            private SalusLogger _logger;
            private Dictionary<string, SalusModuleInfo> _loadedModules = new Dictionary<string, SalusModuleInfo>();
            private DigitalSignatureVerifier _signatureVerifier;

            public ModuleManager(SalusLogger logger)
            {
                _logger = logger;
                _signatureVerifier = new DigitalSignatureVerifier(_logger);
            }

            public async Task<bool> LoadPlugin(string pluginPath)
            {
                _logger.LogInfo($"Attempting to load plugin: {pluginPath}");

                if (!File.Exists(pluginPath))
                {
                    _logger.LogError($"Plugin file not found: {pluginPath}");
                    return false;
                }

                // 4.4 外掛驗證：需經數位簽章與版本比對後方可載入。
                if (!_signatureVerifier.VerifyFileSignature(pluginPath))
                {
                    _logger.LogError($"Plugin '{pluginPath}' failed digital signature verification. Loading aborted.");
                    throw new SecurityError($"Plugin '{pluginPath}' failed digital signature verification.");
                }

                try
                {
                    // For .NET Core, AssemblyLoadContext is preferred for isolation.
                    var context = new PluginLoadContext(pluginPath);
                    Assembly assembly = context.LoadFromAssemblyName(new AssemblyName(Path.GetFileNameWithoutExtension(pluginPath)));

                    var pluginTypes = assembly.GetTypes().Where(t => typeof(ISalusPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);
                    foreach (var type in pluginTypes)
                    {
                        ISalusPlugin plugin = Activator.CreateInstance(type) as ISalusPlugin;
                        if (plugin != null)
                        {
                            if (!CheckPluginCompatibility(plugin))
                            {
                                _logger.LogError($"Plugin '{plugin.Name}' version or dependency mismatch.");
                                throw new SecurityError($"Plugin '{plugin.Name}' incompatible version or dependencies.");
                            }
                            plugin.Initialize(_logger); // Pass logger for plugin logging
                            _loadedModules[plugin.Name] = new SalusModuleInfo(plugin.Name, plugin.Version, pluginPath, context);
                            _logger.LogInfo($"Plugin '{plugin.Name}' (v{plugin.Version}) loaded successfully.");
                            return true;
                        }
                    }
                    _logger.LogWarn($"No valid ISalusPlugin found in assembly: {pluginPath}");
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to load plugin '{pluginPath}': {ex.Message}", ex);
                    throw new RuntimeError($"Failed to load plugin '{pluginPath}': {ex.Message}", inner: ex);
                }
            }

            private bool CheckPluginCompatibility(ISalusPlugin plugin)
            {
                _logger.LogDebug($"Checking compatibility for plugin '{plugin.Name}' v{plugin.Version}...");
                // Example: Compare with current Salus Engine version
                Version salusEngineVersion = Assembly.GetExecutingAssembly().GetName().Version;
                if (Version.TryParse(plugin.RequiredSalusVersion, out Version requiredVersion) && salusEngineVersion < requiredVersion)
                {
                    _logger.LogError($"Plugin '{plugin.Name}' requires Salus v{plugin.RequiredSalusVersion} but current is v{salusEngineVersion}.");
                    return false;
                }
                // TODO: Implement dependency checking (e.g., if plugin requires other Salus modules)
                return true;
            }
        }

        // Placeholder for plugin interface
        public interface ISalusPlugin
        {
            string Name { get; }
            string Version { get; }
            string RequiredSalusVersion { get; }
            IEnumerable<string> Dependencies { get; }
            void Initialize(SalusLogger logger);
            // Methods for plugin to register functions, types, etc. into Salus runtime
            void Register(Scope globalScope, PermissionManager permissionManager);
        }

        public class SalusModuleInfo
        {
            public string Name { get; }
            public string Version { get; }
            public string Path { get; }
            public AssemblyLoadContext LoadContext { get; }

            public SalusModuleInfo(string name, string version, string path, AssemblyLoadContext loadContext)
            {
                Name = name;
                Version = version;
                Path = path;
                LoadContext = loadContext;
            }
        }

        // Simplified PluginLoadContext for isolation
        public class PluginLoadContext : AssemblyLoadContext
        {
            private readonly string _pluginPath;
            private readonly AssemblyDependencyResolver _resolver;

            public PluginLoadContext(string pluginPath) : base(isCollectible: true)
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
                return null; // Fallback to default load context
            }

            protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
            {
                string libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
                if (libraryPath != null)
                {
                    return LoadUnmanagedDllFromPath(libraryPath);
                }
                return IntPtr.Zero; // Fallback to default load context
            }
        }

        // 4. 錯誤與日誌系統：提供統一格式的錯誤追蹤與日誌輸出，支援加密與簽章防竄改。
        public enum LogLevel { Debug, Info, Warn, Error, Critical }

        public class SalusLogger
        {
            private readonly string _logFilePath;
            private readonly byte[] _encryptionKey; // For AES encryption
            private readonly byte[] _signingKey; // For HMAC signing
            private readonly object _lock = new object();

            public SalusLogger(string logFilePath, string encryptionKeyBase64, string signingKeyBase64)
            {
                _logFilePath = logFilePath;
                _encryptionKey = Convert.FromBase64String(encryptionKeyBase64);
                _signingKey = Convert.FromBase64String(signingKeyBase64);

                Directory.CreateDirectory(Path.GetDirectoryName(_logFilePath));
            }

            public void Log(LogLevel level, string message, Exception exception = null)
            {
                if (level < LogLevel.Info) return; // Adjust minimum log level as needed

                string logEntry = FormatLogEntry(level, message, exception);
                string signedAndEncryptedEntry = SignAndEncryptLogEntry(logEntry);

                lock (_lock)
                {
                    File.AppendAllText(_logFilePath, signedAndEncryptedEntry + Environment.NewLine);
                }
            }

            private string FormatLogEntry(LogLevel level, string message, Exception exception)
            {
                string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff zzz");
                string formattedMessage = $"[{timestamp}] [{level}] {message}";
                if (exception != null)
                {
                    formattedMessage += $"{Environment.NewLine}{exception.ToString()}";
                }
                return formattedMessage;
            }

            private string SignAndEncryptLogEntry(string logEntry)
            {
                // Encryption (AES)
                byte[] encryptedBytes;
                byte[] iv;
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = _encryptionKey;
                    aesAlg.GenerateIV();
                    iv = aesAlg.IV;

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                            {
                                swEncrypt.Write(logEntry);
                            }
                            encryptedBytes = msEncrypt.ToArray();
                        }
                    }
                }

                // Prepend IV to encrypted data for decryption: IV_LENGTH:IV:ENCRYPTED_DATA
                byte[] ivLength = BitConverter.GetBytes(iv.Length);
                byte[] dataToSign = ivLength.Concat(iv).Concat(encryptedBytes).ToArray();

                string signature;
                using (HMACSHA256 hmac = new HMACSHA256(_signingKey))
                {
                    byte[] hashBytes = hmac.ComputeHash(dataToSign);
                    signature = Convert.ToBase64String(hashBytes);
                }

                return $"{signature}:{Convert.ToBase64String(dataToSign)}";
            }

            public void LogDebug(string message) => Log(LogLevel.Debug, message);
            public void LogInfo(string message) => Log(LogLevel.Info, message);
            public void LogWarn(string message) => Log(LogLevel.Warn, message);
            public void LogError(string message, Exception ex = null) => Log(LogLevel.Error, message, ex);
            public void LogCritical(string message, Exception ex = null) => Log(LogLevel.Critical, message, ex);
        }

        public class ErrorTracker
        {
            private readonly SalusLogger _logger;
            private readonly List<SalusException> _errors = new List<SalusException>();

            public bool HasErrors => _errors.Any();

            public ErrorTracker(SalusLogger logger)
            {
                _logger = logger;
            }

            public void ReportError(SalusException error)
            {
                _errors.Add(error);
                _logger.LogError(error.ToString(), error);
            }

            public void ReportError(string message, SourceLocation location, ErrorLevel level = ErrorLevel.Error)
            {
                SalusException error = level switch
                {
                    ErrorLevel.Syntax => new SyntaxError(message, location),
                    ErrorLevel.Runtime => new RuntimeError(message, location),
                    ErrorLevel.Security => new SecurityError(message, location),
                    _ => new RuntimeError(message, location),
                };
                ReportError(error);
            }

            public void LogErrors()
            {
                foreach (var error in _errors)
                {
                    // Errors are already logged by ReportError, this just clears the list
                }
            }

            public void ClearErrors()
            {
                _errors.Clear();
            }

            public enum ErrorLevel { Syntax, Runtime, Security, Error }
        }

        // 4. 安全與權限模型
        public enum PermissionType
        {
            None,
            FileSystemRead,
            FileSystemWrite,
            NetworkAccess,
            ExecuteExternalCommand,
            LoadPlugin,
            // ... other permissions
        }

        public class PermissionManager
        {
            private readonly Dictionary<PermissionType, HashSet<string>> _allowedResources = new Dictionary<PermissionType, HashSet<string>>();
            private readonly SalusLogger _logger;

            public PermissionManager(SalusLogger logger)
            {
                _logger = logger;
            }

            public void Allow(PermissionType type, string resourceIdentifier)
            {
                if (!_allowedResources.ContainsKey(type))
                {
                    _allowedResources[type] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                }
                _allowedResources[type].Add(resourceIdentifier);
                _logger.LogDebug($"Permission granted for {type} to resource: {resourceIdentifier}");
            }

            public bool CheckPermission(PermissionType type, string resourceIdentifier)
            {
                if (!_allowedResources.TryGetValue(type, out var allowedSet))
                {
                    _logger.LogWarn($"Permission type '{type}' is not configured. Denying access to '{resourceIdentifier}'.");
                    return false; // Deny if permission type not explicitly configured
                }

                // Special handling for file system paths: check if the path is within any allowed prefix
                if (type == PermissionType.FileSystemRead || type == PermissionType.FileSystemWrite)
                {
                    string fullPath = Path.GetFullPath(resourceIdentifier);
                    foreach (var allowedPath in allowedSet)
                    {
                        string fullAllowedPath = Path.GetFullPath(allowedPath);
                        if (fullPath.StartsWith(fullAllowedPath, StringComparison.OrdinalIgnoreCase))
                        {
                            _logger.LogDebug($"Permission granted for {type} to {resourceIdentifier} (matched by {allowedPath}).");
                            return true;
                        }
                    }
                    _logger.LogWarn($"Permission denied for {type}: {resourceIdentifier} (no matching allowed path).");
                    return false;
                }

                // For other types (e.g., command names, network hosts) direct match
                bool granted = allowedSet.Contains(resourceIdentifier);
                if (!granted)
                {
                    _logger.LogWarn($"Permission denied for {type}: {resourceIdentifier}.");
                }
                return granted;
            }
        }

        public class DigitalSignatureVerifier
        {
            private SalusLogger _logger;

            public DigitalSignatureVerifier(SalusLogger logger)
            {
                _logger = logger;
            }

            public bool VerifyFileSignature(string filePath)
            {
                // In a real system, this would involve:
                // 1. Loading the file and its digital signature (e.g., Authenticode on Windows, or a separate .sig file for GPG).
                // 2. Hashing the file content (excluding signature block if embedded).
                // 3. Verifying the signature against the hash using a trusted public key/certificate.
                // 4. Checking certificate revocation status, expiry, etc.

                _logger.LogWarn($"Digital signature verification for '{filePath}' is a placeholder. Returning TRUE for demonstration.");
                return true;
            }
        }

        // 3. CLI 互動層設計
        public class SalusCLI
        {
            private SalusEngine _engine;
            private SalusLogger _logger;
            private PermissionManager _permissionManager;

            public SalusCLI(SalusEngine engine, SalusLogger logger, PermissionManager permissionManager)
            {
                _engine = engine;
                _logger = logger;
                _permissionManager = permissionManager;
            }

            public async Task StartInteractiveMode()
            {
                _logger.LogInfo("Salus CLI interactive mode started. Type 'exit' to quit.");
                // For full CLI features (syntax highlighting, history, autocompletion),
                // a library like 'ReadLine' or 'Spectre.Console' would be integrated here.

                while (true)
                {
                    Console.Write("salus> ");
                    string input = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(input)) continue;
                    if (input.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase)) break;
                    if (input.Trim().Equals("help", StringComparison.OrdinalIgnoreCase))
                    {
                        PrintHelp();
                        continue;
                    }

                    try
                    {
                        SalusValue result = await _engine.Execute(input, "eval");
                        if (result.Type == SalusType.Error && result.Value is SalusException salusEx)
                        {
                            Console.WriteLine($"Error: {salusEx}");
                        }
                        else if (result != SalusValue.Null) // Don't print null results in REPL by default
                        {
                            Console.WriteLine($"=> {result}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"CLI execution error: {ex.Message}", ex);
                        Console.WriteLine($"CLI Internal Error: {ex.Message}");
                    }
                }
                _logger.LogInfo("Salus CLI interactive mode exited.");
            }

            public async Task RunScript(string filePath)
            {
                _logger.LogInfo($"Running script: {filePath}");

                if (!File.Exists(filePath))
                {
                    _logger.LogError($"Script file not found: {filePath}");
                    Console.WriteLine($"Error: Script file not found at '{filePath}'");
                    return;
                }

                if (!_permissionManager.CheckPermission(PermissionType.FileSystemRead, filePath))
                {
                    _logger.LogError($"Permission denied to read script file: {filePath}");
                    Console.WriteLine($"Error: Permission denied to read script file '{filePath}'");
                    return;
                }

                try
                {
                    string scriptContent = await File.ReadAllTextAsync(filePath);
                    SalusValue result = await _engine.Execute(scriptContent, "script", filePath);
                    if (result.Type == SalusType.Error && result.Value is SalusException salusEx)
                    {
                        Console.WriteLine($"Script Error: {salusEx}");
                        Environment.ExitCode = 1; // Indicate error
                    }
                    else
                    {
                        _logger.LogInfo($"Script '{filePath}' finished. Result: {result}");
                        Environment.ExitCode = 0;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error running script '{filePath}': {ex.Message}", ex);
                    Console.WriteLine($"Error running script '{filePath}': {ex.Message}");
                    Environment.ExitCode = 1;
                }
            }

            public async Task ExecExternalCommand(string commandLine)
            {
                _logger.LogInfo($"Attempting to execute external command: {commandLine}");

                var parts = commandLine.Split(' ', 2);
                string command = parts[0];
                string arguments = parts.Length > 1 ? parts[1] : string.Empty;

                if (!_permissionManager.CheckPermission(PermissionType.ExecuteExternalCommand, command))
                {
                    _logger.LogError($"Security Error: Permission denied to execute external command '{command}'.");
                    Console.WriteLine($"Security Error: Permission denied to execute external command '{command}'.");
                    Environment.ExitCode = 1;
                    return;
                }

                try
                {
                    // This is a simplified example. A real "sandboxed" execution
                    // would involve process isolation, limiting environment variables,
                    // I/O redirection to specific allowed paths, etc.
                    using (System.Diagnostics.Process process = new System.Diagnostics.Process())
                    {
                        process.StartInfo.FileName = command;
                        process.StartInfo.Arguments = arguments;
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.RedirectStandardError = true;
                        process.StartInfo.CreateNoWindow = true;

                        process.Start();

                        string output = await process.StandardOutput.ReadToEndAsync();
                        string error = await process.StandardError.ReadToEndAsync();

                        await process.WaitForExitAsync();

                        _logger.LogInfo($"External command '{command}' exited with code {process.ExitCode}.");
                        if (!string.IsNullOrEmpty(output))
                        {
                            Console.WriteLine(output);
                        }
                        if (!string.IsNullOrEmpty(error))
                        {
                            Console.Error.WriteLine(error); // Write errors to stderr
                        }
                        Environment.ExitCode = process.ExitCode;
                    }
                }
                catch (System.ComponentModel.Win32Exception ex)
                {
                    _logger.LogError($"Failed to start external command '{command}': {ex.Message}", ex);
                    Console.Error.WriteLine($"Error: Failed to start command '{command}'. Check if it's installed and in PATH. ({ex.Message})");
                    Environment.ExitCode = 1;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error during external command execution: {ex.Message}", ex);
                    Console.Error.WriteLine($"Error executing command: {ex.Message}");
                    Environment.ExitCode = 1;
                }
            }

            public void PrintHelp()
            {
                Console.WriteLine("Salus CLI Help:");
                Console.WriteLine("  salus               - Start interactive shell.");
                Console.WriteLine("  salus run <file>    - Execute a Salus script file.");
                Console.WriteLine("  salus eval <code>   - Evaluate a single Salus expression.");
                Console.WriteLine("  salus exec <cmd>    - Execute an external system command (if permitted).");
                Console.WriteLine("  salus diag          - Show diagnostic information.");
                Console.WriteLine("  salus --help / -h   - Display this help message.");
                Console.WriteLine("\nFor more details, visit the Salus official website.");
            }
        }
    }

    // Main entry point for the Salus application
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Configuration for Logger and PermissionManager
            string logFilePath = Path.Combine(AppContext.BaseDirectory, "logs", "salus.log");
            string encryptionKeyBase64 = Environment.GetEnvironmentVariable("SALUS_ENCRYPTION_KEY") ?? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw=="; // 32 bytes for AES-256
            string signingKeyBase64 = Environment.GetEnvironmentVariable("SALUS_SIGNING_KEY") ?? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw=="; // 32 bytes for HMAC-SHA256

            // Generate dummy keys if they are still defaults (not secure for production!)
            if (encryptionKeyBase64.Equals("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw==") || signingKeyBase64.Equals("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw=="))
            {
                Console.WriteLine("WARNING: Using default encryption and signing keys. Please set SALUS_ENCRYPTION_KEY and SALUS_SIGNING_KEY environment variables for production.");
                using (Aes aesAlg = Aes.Create()) { aesAlg.GenerateKey(); encryptionKeyBase64 = Convert.ToBase64String(aesAlg.Key); }
                using (HMACSHA256 hmac = new HMACSHA256()) { hmac.GenerateKey(); signingKeyBase64 = Convert.ToBase64String(hmac.Key); }
            }

            SalusLogger logger = new SalusLogger(logFilePath, encryptionKeyBase64, signingKeyBase64);
            PermissionManager permissionManager = new PermissionManager(logger);

            // Configure default permissions (to be loaded from config in real app)
            permissionManager.Allow(Salus.SalusEngine.PermissionType.FileSystemRead, AppContext.BaseDirectory);
            permissionManager.Allow(Salus.SalusEngine.PermissionType.FileSystemRead, Path.Combine(AppContext.BaseDirectory, "scripts"));
            permissionManager.Allow(Salus.SalusEngine.PermissionType.FileSystemWrite, Path.Combine(AppContext.BaseDirectory, "output"));

            // Example external command permissions (platform-specific)
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "cmd");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "powershell");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "dir");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "type");
            }
            else // Linux/macOS
            {
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "bash");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "sh");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "ls");
                permissionManager.Allow(Salus.SalusEngine.PermissionType.ExecuteExternalCommand, "cat");
            }

            SalusEngine engine = new SalusEngine(logger, permissionManager);
            SalusCLI cli = new SalusCLI(engine, logger, permissionManager);

            if (args.Length == 0)
            {
                await cli.StartInteractiveMode();
            }
            else
            {
                string command = args[0].ToLowerInvariant();
                switch (command)
                {
                    case "run":
                        if (args.Length > 1) await cli.RunScript(args[1]);
                        else Console.WriteLine("Usage: salus run <script_file>");
                        break;
                    case "eval":
                        if (args.Length > 1) await engine.Execute(string.Join(" ", args.Skip(1)), "eval");
                        else Console.WriteLine("Usage: salus eval <code>");
                        break;
                    case "exec":
                        if (args.Length > 1) await cli.ExecExternalCommand(string.Join(" ", args.Skip(1)));
                        else Console.WriteLine("Usage: salus exec <command_line>");
                        break;
                    case "--help":
                    case "-h":
                        cli.PrintHelp();
                        break;
                    case "diag":
                        Console.WriteLine("Salus Diagnostic Report:");
                        Console.WriteLine($"  Salus Engine Version: {Assembly.GetExecutingAssembly().GetName().Version}");
                        Console.WriteLine($"  .NET Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
                        Console.WriteLine($"  OS: {System.Runtime.InteropServices.RuntimeInformation.OSDescription} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})");
                        Console.WriteLine($"  Log File: {logFilePath}");
                        Console.WriteLine($"  Base Directory: {AppContext.BaseDirectory}");
                        // TODO: Add more detailed diagnostics, e.g., loaded modules, memory usage, environment variables
                        logger.LogInfo("Diagnostic report generated.");
                        break;
                    default:
                        Console.WriteLine($"Unknown command: {command}");
                        cli.PrintHelp();
                        Environment.ExitCode = 1;
                        break;
                }
            }
        }
    }

    public enum TokenType { Identifier, Keyword, String, Number, Operator, Separator, Eof }

    public class Token
    {
        public TokenType Type { get; }
        public string Value { get; }
        public Salus.SalusEngine.SourceLocation Location { get; }
        public Token(TokenType type, string value, Salus.SalusEngine.SourceLocation location) { Type = type; Value = value; Location = location; }
        public override string ToString() => $"[{Type}] '{Value}' at {Location}";
    }
}