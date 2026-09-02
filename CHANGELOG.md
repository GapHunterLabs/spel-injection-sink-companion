<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# SpEL Injection Sink Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Hand-written SpEL tokenizer + recursive-descent parser (this
  catalog's second full custom grammar).
- Tainted-argument detection: same-method, one-hop taint from an HTTP
  endpoint parameter to `ExpressionParser.parseExpression(...)`
  (CWE-917, the CVE-2022-22963 mechanism).
- Hardcoded-dangerous-type detection: a compile-time-constant
  expression whose parsed AST references `T(Runtime)`,
  `T(ProcessBuilder)`, `T(System)`, `T(Class)`, or `T(ClassLoader)`.

[Unreleased]: https://github.com/GapHunterLabs/spel-injection-sink-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/spel-injection-sink-companion/commits/0.1.0
