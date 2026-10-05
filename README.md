# SpEL Injection Sink Companion

Flags a Spring `ExpressionParser.parseExpression(...)` call whose
argument is built from an HTTP endpoint parameter, or is a hardcoded
constant referencing a dangerous `T(...)` type.

## Why it exists

CWE-917 (Expression Language Injection) -- the exact mechanism
CVE-2022-22963 (Spring Cloud Function) exploited: an attacker's raw
HTTP input becomes SpEL SOURCE TEXT, re-parsed and evaluated. Real
competitors exist for the general category, stated honestly rather
than claiming zero competition: CodeQL (batch/CI only, not inline
IDE), Datadog Code Security (a real JetBrains plugin, but one rule
among 500+ in an enterprise SAST requiring a Datadog account/
subscription), Qodana taint analysis (a real JetBrains plugin,
requires a paid Ultimate Plus license -- does not run on Community
Edition). None is a free, zero-account, Community-Edition-compatible,
single-purpose plugin for this exact finding.

## Why built this way

- **A real hand-written SpEL parser** -- the second full custom
  grammar in this catalog, after `redos-catastrophic-backtracking-
  companion`'s own regex grammar. Tokenizer + recursive-descent parser
  building a real AST (property access, method calls, `T(...)` type
  references, constructor calls) -- never depends on Spring itself
  being on the classpath, and never evaluates the expression, only
  asks whether it structurally contains a `T(...)` node.
- **Two independent, honestly-scoped findings, not one conflated
  check:**
  1. **Tainted argument** -- same-method, one-hop taint from an HTTP
     endpoint parameter (same discipline as `unsafe-deserialization-
     sink-companion`'s own finder) to the `parseExpression` argument.
     Flagged unconditionally once taint is confirmed -- the attacker
     controls the substituted text's shape, so no additional AST-shape
     gate would be sound here.
  2. **Hardcoded dangerous type** -- when the argument is a genuine
     compile-time constant (real IntelliJ constant folding via
     `JavaPsiFacade`'s `ConstantEvaluationHelper`, never a hand-rolled
     literal check), its parsed AST is checked for a `T(...)`
     reference to `Runtime`/`ProcessBuilder`/`System`/`Class`/
     `ClassLoader` -- the concrete classes real SpEL RCE payloads use.
- **`looksLikeExpressionParser` is a declared-type-TEXT heuristic**,
  never resolved against the real Spring classpath -- works even in a
  project/test with no Spring dependency present, same reasoning
  `unsafe-deserialization-sink-companion` uses for `ObjectInputStream`
  by simple name only.

## v0.1 scope — stated honestly, not exhaustively

- Only Java; only same-method taint (case 1 never crosses a method
  boundary, never resolves a value assigned across multiple
  intermediate variables).
- Never distinguishes `SimpleEvaluationContext` (restricted) from
  `StandardEvaluationContext` (full power) at the `.getValue(...)`
  call site -- left for a future version.
- The dangerous-type list for case 2 is fixed and curated (5 classes)
  -- never a general "any `T(...)` is suspicious" rule, which would
  flag entirely ordinary expressions like `T(java.lang.Math).PI`.

## Usage

Open a Java file with a Spring MVC/JAX-RS endpoint method that builds a
SpEL expression from a request parameter, or a hardcoded expression
referencing `T(java.lang.Runtime)` (or similar) -- the
`parseExpression(...)` call shows a warning.

## Support

- **Bugs and feature requests:** [GitHub Issues](https://github.com/GapHunterLabs/spel-injection-sink-companion/issues)
- **Questions, or custom rules for a team's codebase:** **gaphunterlabs@gmail.com**
- **Security vulnerabilities:** report privately as described in [SECURITY.md](SECURITY.md), not in a public issue.
- **Privacy and network behavior:** [PRIVACY.md](PRIVACY.md)

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
