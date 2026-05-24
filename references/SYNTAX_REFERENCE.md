---
description: >-
  RouterOS .rsc file syntax reference for validation. Covers line structure,
  data types, operators, control flow, export/import format, common syntax
  errors, RouterOS v6 vs v7 differences, and idempotent pattern validation.
---

# RouterOS .rsc Syntax Reference

## 1. File Structure

### 1.1 Comment Format

Comments begin with `#` and extend to end of line. No block comments exist.

```rsc
# This is a comment
:put "hello" # inline comment
```

Inside quoted strings, `#` has no special meaning. The `#` character in `:error`
or `:log` messages does not start a comment.

### 1.2 Line Continuation

A trailing backslash `\` continues the command on the next line. The backslash
and the newline character itself are consumed — the continuation line is joined
as if it were on the same line.

```rsc
/ip firewall filter add chain=input \
  protocol=tcp dst-port=22 \
  src-address=10.0.0.0/24 \
  action=accept
```

**Rules:**
- The `\` must be the **last character before the newline** — no trailing spaces or
  comments after `\`.
- A continuation cannot break a token in the middle (must break between tokens
  or after `/` in a path prefix).
- RouterOS v6.48+ and all v7 versions support this. Earlier v6 releases may not.

### 1.3 Line Structure

Every command line follows this grammar:

```
[prefix] [path] command [uparam] [param=value]... [;]
```

| Component      | Description                                                     |
|----------------|-----------------------------------------------------------------|
| `prefix`       | `:` global command modifier (e.g., `:global`, `:local`, `:if`)  |
| `path`         | `/`-separated menu path (e.g., `/ip firewall filter`)           |
| `command`      | Menu command (`add`, `set`, `print`, `export`, etc.)            |
| `uparam`       | Unnamed parameter (positional), often a number or ID            |
| `param=value`  | Named parameter with `=` assignment                             |
| `;`            | Optional statement terminator                                   |

### 1.4 Whitespace Rules

| Rule                                              | Example                         |
|---------------------------------------------------|---------------------------------|
| Tokens separated by one or more spaces or tabs    | `add chain=input action=drop`   |
| **No spaces around `=`** — `name = value` parses as three tokens | `src-addr=10.0.0.1`     |
| Strings with spaces must be quoted                | `comment="my rule"`            |
| Multiple spaces between tokens collapsed          | `add  chain=input` is valid     |
| Leading/trailing whitespace on a line ignored     | `  /ip route  ` is valid        |

**Critical:** `name = value` (with spaces around `=`) is NOT valid. The parser
treats this as two separate tokens: the parameter name `name` (without its value)
followed by `=` and `value` as unrelated tokens. This causes silent config errors.

### 1.5 Line Termination

Commands may be terminated with a semicolon `;` or a newline. Multiple commands
on one line require `;` between them:

```rsc
:local a 1; :local b 2; :put "sum=$($a + $b)"
```

The semicolon is optional before a newline. Inside `{}` block bodies, each
statement may optionally end with `;`.

### 1.6 Block Structure

`{ }` denote block bodies for control flow, script commands, and function bodies:

```rsc
:if ($count > 10) do={
  :put "threshold exceeded"
  :log warning "count=$count"
}
```

**Rules:**
- The opening `{` may be on the same line as `do={}`, `else={}`, or `do { } while={}`.
- Nested blocks are supported up to available memory limits.
- A block without any statements is valid: `{}` (empty block).
- Blocks return the value of their last evaluated expression.

### 1.7 Data Types

RouterOS uses dynamic typing. Variables take their type from the assigned value.

| Type        | Description                              | Examples                                      |
|-------------|------------------------------------------|-----------------------------------------------|
| `num`       | 64-bit signed integer                    | `42`, `-1`, `0x1F` (hex), `0b101` (binary)   |
| `bool`      | Boolean true/false                       | `true`, `false`, `yes`, `no`                  |
| `str`       | Unicode string, may be quoted            | `hello`, `"hello world"`                      |
| `ip`        | IPv4 or IPv6 address                     | `10.0.0.1`, `::1`, `2001:db8::1`             |
| `ip-prefix` | IP address with prefix length            | `10.0.0.0/24`, `2001:db8::/32`               |
| `id`        | Internal numeric ID (menu item pointer)  | `*1`, `*2`, `*FFF2` (hex)                    |
| `time`      | Time interval                            | `1d2h3m4s`, `30s`, `00:00:30`                |
| `array`     | Ordered sequence of values               | `{1;2;3}`, `{key=val; a=1}`                 |
| `nil`       | Absence of value                         | `nothing`, `[:nothing]`                      |

**Type coercion rules:**
- In string context, most types auto-convert to string representation.
- In numeric context, strings that start with digits are parsed; non-numeric
  strings produce `0`.
- `true`/`yes` coerce to `1` in numeric context, `false`/`no` coerce to `0`.
- `nil` (returned by `[:nothing]`) coerces to empty string `""`.

### 1.8 String Escape Sequences

Inside double-quoted `"..."` strings:

| Escape | Meaning                    |
|--------|----------------------------|
| `\n`   | Newline                    |
| `\r`   | Carriage return            |
| `\t`   | Tab                        |
| `\"`   | Literal double-quote       |
| `\\`   | Literal backslash          |
| `\_`   | Non-breaking space         |
| `\00`  | Arbitrary byte (hex pair)  |

Single-quoted `'...'` strings do **not** process escape sequences (literal mode).

```rsc
:put "line1\nline2"      # three-line output with embedded newline
:put 'line1\nline2'      # literal: line1\nline2
:put "\"quoted\""        # "quoted"
```

### 1.9 Type Conversion Functions

| Function      | Description                        | Example                               |
|---------------|------------------------------------|---------------------------------------|
| `tonum(val)`  | Convert to integer                 | `tonum("42")` → `42`                  |
| `tobool(val)` | Convert to boolean                 | `tobool("yes")` → `true`              |
| `tostr(val)`  | Convert to string                  | `tostr(42)` → `"42"`                 |
| `toip(val)`   | Convert to IP address              | `toip("10.0.0.1")`                    |
| `toarray(val)`| Convert to array                   | `toarray("a,b")` → `{a; b}`          |
| `totime(val)` | Convert to time interval           | `totime("30s")`                       |

All conversion functions return `nothing` on failure instead of raising an error.

## 2. Variables & Scope

### 2.1 Declaration and Scoping

| Keyword     | Scope                                      | Lifetime                           |
|-------------|--------------------------------------------|------------------------------------|
| `:global`   | All scripts, all functions, persistent     | Until RouterOS restart or `:undefine` |
| `:local`    | Current script or function body only       | Until the script/function exits    |

```rsc
:global myVar "persistent value"
:local tempVar "local value"

:myFunc do={
  :global myVar    # must re-declare :global inside functions to access
  :local tempVar   # separate local scope inside the function
  :put $myVar      # accesses the global
}
```

**Key scoping rules:**
- A `:global` var declared in one script is visible to all scripts (including
  scheduler scripts, console scripts, etc.).
- Inside a function `do={}`, you must use `:global varname` (without assigning)
  to access an existing global. Without re-declaring it, the global is not in
  scope and a local with the same name shadows it.
- `:local` declarations in nested blocks inside the same function share the
  function's scope (not block-scoped like C/JS).

### 2.2 Reserved Variable Name Conflicts

RouterOS scripts share a flat variable namespace with menu item parameter names.
This creates a subtle trap: using a parameter name as a variable inside a menu's
`find` or script context can shadow or conflict.

**Known conflict-prone names:**

| Variable Name   | Where It Conflicts                                   |
|-----------------|-------------------------------------------------------|
| `type`          | Interface `/interface print`, `/ip address print`     |
| `name`          | Every item (`/user`, `/interface`, `/system identity`)|
| `address`       | `/ip address`, `/ip firewall nat` dst-nat             |
| `interface`     | `/ip address`, `/route`, `/dhcp-client`               |
| `number`        | Implicit column in `print` output                     |
| `value`         | Return placeholder in `/export`                       |
| `data`          | DNS static records, firewall address-lists            |
| `key`           | Array key in `:foreach`                               |
| `status`        | Link status columns                                   |
| `comment`       | Almost every item                                     |
| `chain`         | `/ip firewall filter`, `/ip firewall nat`             |
| `protocol`      | `/ip firewall`, `/ip service`                         |
| `disabled`      | Almost every item                                     |
| `running`       | Interface status                                      |
| `mac-address`   | `/interface ethernet`, `/ip neighbor`                 |

**Why this matters:** When you write:

```rsc
:local address "10.0.0.1"
/ip address print where address=$address
```

The `$address` in `where=` resolves to the local variable, not the column — which
is actually what you want here. But the confusion becomes problematic when you
accidentally shadow a column you intended to match.

**Rule of thumb:** Avoid using menu column names as local variables inside
`print where=` or `find` expressions when the value is meant to reference
that column.

### 2.3 Unsetting Variables

```rsc
:global myVar
:undefine myVar        # RouterOS v7+ — removes variable entirely
:set myVar nothing     # Sets to nil (value is nothing, variable still exists)
```

Before v7.18/7.16, `:set myVar nothing` was the standard way. `:undefine` is
cleaner and preferred for v7+.

### 2.4 Empty Array Definition

The idiom for creating an empty array:

```rsc
:local emptyArr [:toarray ""]
:put [:len $emptyArr]  # 0
```

`{}` alone is **not valid** for creating an empty array — it causes a parse
error (see §8.2). `{}` is only valid with semicolon-separated elements inside.

## 3. Operators

### 3.1 Arithmetic Operators

| Operator | Description     | Example                  |
|----------|-----------------|--------------------------|
| `+`      | Addition        | `$a + 1`                 |
| `-`      | Subtraction     | `$a - 1`                 |
| `*`      | Multiplication  | `$a * 2`                 |
| `/`      | Division        | `$a / 2`                 |
| `%`      | Modulo          | `$a % 2`                 |
| `-`      | Unary negation  | `-$a`                    |

**⚠ Division ambiguity:** `10/2` is **parsed as an IP address** (`10.0.0.2`),
not as `10 divided by 2`. Always use spaces around `/` for division:
`10 / 2` → 5. See §8.3 for details.

### 3.2 Relational Operators

| Operator | Description             | Example                     |
|----------|-------------------------|-----------------------------|
| `=`      | Equal (value)           | `$a = 10`                   |
| `!=`     | Not equal               | `$a != 10`                  |
| `<`      | Less than               | `$a < 10`                   |
| `>`      | Greater than            | `$a > 10`                   |
| `<=`     | Less than or equal      | `$a <= 10`                  |
| `>=`     | Greater than or equal   | `$a >= 10`                  |
| `~`      | Regex match             | `$str ~ "^10\."`           |
| `!~`     | Regex no match          | `$str !~ "^10\."`          |

### 3.3 Logical Operators

| Operator | Description | Example                           |
|----------|-------------|-----------------------------------|
| `&&`     | Logical AND | `$a > 5 && $a < 10`              |
| `\|\|`   | Logical OR  | `$a = 0 \|\| $a = nothing`       |
| `!`      | Logical NOT | `!($a = 0)`                       |

**Short-circuit evaluation:** `&&` and `||` short-circuit — the right operand is
evaluated only if the left operand determines the result.

### 3.4 Bitwise Operators

| Operator | Description     | Example           |
|----------|-----------------|-------------------|
| `~`      | Bitwise NOT     | `~$flags`         |
| `&`      | Bitwise AND     | `$flags & 0x01`   |
| `\|`     | Bitwise OR      | `$flags \| 0x02`  |
| `^`      | Bitwise XOR     | `$flags ^ 0x03`   |
| `<<`     | Left shift      | `1 << 8`          |
| `>>`     | Right shift     | `256 >> 8`        |

### 3.5 String Concatenation

| Operator | Description           | Example                      |
|----------|-----------------------|------------------------------|
| `.`      | String concatenation  | `"hello " . "world"`        |

```rsc
:local a "hello"
:local b "world"
:put ($a . " " . $b)   # "hello world"
```

**⚠ Pitfall:** You cannot directly concatenate a string to an array or an array
to a string — the `.` operator on non-string types triggers `tostr()` coercion
on each operand first, which may produce unexpected results.

### 3.6 Command Substitution `[...]`

Square brackets execute a command and substitute its return value:

```rsc
:local now [/system clock get time]
:local count [:len [/ip firewall filter find]]
```

**Nesting:** `[[command]]` is a subquery inside a subquery; the outer brackets
use the result of the inner command.

**Return value rules:**
- `get` returns the value of the requested property.
- `find` returns an array of IDs (possibly empty).
- `print as-value` returns an array with named keys.
- Most other commands return `nothing`.

### 3.7 Subexpression `(...)`

Parentheses group expressions for evaluation precedence:

```rsc
:local result (($a + $b) * 2)
:put ("sum: " . ($a + $b))
```

### 3.8 Array Element Access `->`

Access array elements by zero-based index:

```rsc
:local arr {a; b; c}
:put [$arr->0]   # a
:put [$arr->2]   # c
```

**Nested/2D array access:**

```rsc
:local matrix {{1;2}; {3;4}}
:put [$matrix->0->1]   # 2
```

**Index rules:**
- Negative indices count from end: `$arr->-1` is the last element.
- Out-of-bounds access returns `nothing`.
- Array elements are mutable via `:set ($arr->1) "newval"`.

### 3.9 Regex Matching `~`

```rsc
:local ip "10.0.0.1"
:if ($ip ~ "^(10|172\\.16|192\\.168)\\.") do={
  :put "private IP"
}
```

**Notes:**
- Uses POSIX extended regular expressions (ERE), not PCRE.
- Backslashes in patterns require escaping in quoted strings: `"\\."` matches a
  literal dot.
- `!~` is the negation (does not match).
- Empty pattern or invalid regex evaluates to `false`.

### 3.10 String Interpolation `$`

Inside double-quoted strings, `$varname` is expanded:

```rsc
:local name "world"
:put "hello $name"       # hello world
:put "value=$($a + $b)"  # value=42  (expression substitution)
```

- `$varname` — substitutes the variable value.
- `$(expression)` — evaluates expression and substitutes result.
- `$[command]` — executes command and substitutes return value.
- Use `$$` for a literal `$`.
- Single-quoted `'...'` strings do **not** interpolate.

## 4. Global Commands

All global commands begin with `:` and are available at any menu level.

| Command            | Description                                           | Example                                   |
|--------------------|-------------------------------------------------------|-------------------------------------------|
| `:global`          | Declare/set a global variable                         | `:global myVar "val"`                     |
| `:local`           | Declare/set a local variable                          | `:local x 1`                             |
| `:set`             | Set an existing variable or array element             | `:set x 2; :set ($arr->1) "b"`          |
| `:put`             | Print value to console                                | `:put "hello"`                            |
| `:log`             | Write message to system log                           | `:log warning "message"`                  |
| `:delay`           | Pause execution (seconds or time)                     | `:delay 1; :delay 500ms`                 |
| `:error`           | Abort script with error message                       | `:error "invalid input"`                  |
| `:execute`         | Run a script in background (returns PID)              | `:execute script="myscript"`             |
| `:parse`           | Parse and execute a constructed command string        | `:parse ":$cmd $arg"`                    |
| `:break`           | Exit current loop                                     | `:foreach v in=$arr do={ :if ($v = 0) do={ :break } }` |
| `:continue`        | Skip to next loop iteration                           | `:continue`                               |
| `:exit`            | Exit current script/function                          | `:exit`                                   |
| `:return`          | Return value from function                            | `:return $result`                         |
| `:len`             | Return length of string or array                      | `:len "abc"` → `3; :len $arr`           |
| `:pick`            | Extract substring or subarray                         | `:pick "abcde" 1 3` → `"bc"`            |
| `:find`            | Find value in a string or array (returns index)       | `:find "hello" "el"` → `1`              |
| `:typeof`          | Return type name of a value                           | `:typeof 42` → `"num"`                   |
| `:environment`     | Print/set environment variables                       | `:environment print`                       |
| `:resolve`         | Resolve hostname to IP address (DNS lookup)           | `:resolve "example.com"`                  |
| `:rndnum`          | Generate random number in range                       | `:rndnum 1 100`                           |
| `:rndstr`          | Generate random string of given length                | `:rndstr 12`                              |
| `:range`           | Generate array of numbers (similar to `seq`)          | `:range 5` → `{0;1;2;3;4}`              |
| `:timestamp`       | Return current time as Unix timestamp (microseconds)  | `:timestamp`                               |
| `:time`            | Measure execution time of a block                     | `:time {:delay 1s}`                       |
| `:beep`            | Play beep sound (frequency, duration)                 | `:beep 440 200`                            |
| `:serialize`       | Convert data structure to a string format             | `:serialize tojson $data`                 |
| `:deserialize`     | Parse a serialized string back to data                | `:deserialize fromjson $str`             |
| `:convert`         | Convert between encoding formats                      | `:convert to base64 $str`                 |
| `:grep`            | Filter array by regex pattern                         | `:grep $arr "^eth"`                      |
| `:jobname`         | Get/set the script execution job name                 | `:jobname`                                |
| `:nothing`         | Return the nil value                                  | `:return [:nothing]`                      |
| `:retry`           | Retry a block on failure                              | `:retry attempts=3 interval=1s do={ ... }`|
| `:onerror`         | Execute fallback on error                             | `:onerror e in={...} do={...}`           |

## 5. Menu-Specific Commands

### 5.1 Command Reference

| Command   | Description                                              |
|-----------|----------------------------------------------------------|
| `add`     | Create a new item in the menu                            |
| `remove`  | Delete an item by ID or lookup                           |
| `set`     | Modify properties of an existing item                    |
| `enable`  | Enable a disabled item (where applicable)                |
| `disable` | Disable an item without removing it                      |
| `get`     | Retrieve a single property value                         |
| `print`   | Display items                                            |
| `export`  | Generate portable configuration output                   |
| `edit`    | Interactive property editor for an item                  |
| `find`    | Return IDs of items matching criteria                    |
| `import`  | Load and execute a `.rsc` file                           |
| `move`    | Reorder items in a list (e.g., firewall rules)           |
| `comment` | Set comment on an item                                   |

### 5.2 Print Parameters

```rsc
/ip firewall filter print [parameter]...
```

| Parameter      | Description                                          |
|----------------|------------------------------------------------------|
| `as-value`     | Return structured data (array of arrays), not display |
| `where=...`    | Filter expression (match item properties)            |
| `count-only`   | Print only the number of matching items              |
| `terse`        | Compact output (one line per item)                   |
| `detail`       | Show all properties including defaults               |
| `brief`        | Default columnar display                             |
| `file=name`    | Write output to a file                               |
| `from=id`      | Start listing from a specific item ID                |
| `interval=s`   | Repeat every N seconds (live monitor)                |

**`where=` syntax:**
```rsc
/ip firewall filter print where chain=input action=accept
/ip address print where interface=ether1 disabled=no
/ip route print where static=yes and gateway~"^10\\."
```

Multiple conditions are ANDed by default. Use `or` for OR logic.

### 5.3 Find Parameters

```rsc
/ip firewall filter find [where=...]
```

- `find` returns an **array of IDs** (e.g., `{*1; *3; *5}`).
- If no items match, returns an empty array `{}`.
- Single-item match still returns an array (length 1).

**Pattern:** `[find where=...]` is the idempotent way to reference items instead
of hardcoded IDs.

### 5.4 Get Parameters

```rsc
/ip address get [find where=interface=ether1] address
```

- Returns the value of a single property from the matched item.
- If `find` matches multiple items, only the first is used.
- Without a property name, returns all properties of the matched item.

### 5.5 Import Parameters

```rsc
/import file=rules.rsc [parameter]...
```

| Parameter       | Description                                        | v6 | v7 |
|-----------------|----------------------------------------------------|----|----|
| `verbose=yes`   | Show each command as it executes                   | ✅ | ✅ |
| `dry-run=yes`   | Validate only, do not apply (v7.16+)              | ❌ | ✅ |
| `from-line=N`   | Start import from a specific line number           | ✅ | ✅ |
| `on-error=...`  | Action on error (`fail` default, `continue`)      | ✅ | ✅ |

**Import behavior:**
- Imports are applied transactionally per command — if one command fails, by
  default the import stops.
- `on-error=continue` skips failed commands and continues.
- `dry-run=yes` (v7.16+) validates syntax and would-apply without modifying
  the running config. Critical for pre-deployment validation.

## 6. Control Flow

### 6.1 Conditional: `:if / else`

```rsc
:if ($x > 10) do={
  :put "greater"
} else={
  :put "less or equal"
}
```

`else` is optional. The condition expression must evaluate to `true`/`false`.
Everything that is not `0`, `false`, `nothing`, `""`, or `{}` is truthy.

**Else-if pattern (chained):**

```rsc
:if ($x > 10) do={
  :put "A"
} else={
  :if ($x > 5) do={
    :put "B"
  } else={
    :put "C"
  }
}
```

**Note:** RouterOS has no `else-if` keyword. Chain `else={ :if ... }` manually.

### 6.2 Numeric Loop: `:for`

```rsc
:for i from=1 to=10 step=1 do={
  :put "$i"
}
```

| Parameter | Description                   | Default |
|-----------|-------------------------------|---------|
| `from`    | Starting value                | 0       |
| `to`      | Endpoint value                | required|
| `step`    | Increment/decrement per iter  | 1       |

- `step` may be negative for descending loops (`to < from`).
- Loops always include both endpoints (inclusive).

### 6.3 Array Loop: `:foreach`

```rsc
:local arr {a; b; c}
:foreach val in=$arr do={
  :put $val
}

# With key capture
:foreach key,val in=$arr do={
  :put "$key → $val"
}

# String iteration (per-character)
:foreach ch in="hello" do={
  :put $ch
}
```

| Parameter | Description                         |
|-----------|-------------------------------------|
| `in`      | Source array or string             |

### 6.4 Conditional Loop: `:while` / `:do-while`

**While** (test before body):

```rsc
:local i 0
:while ($i < 10) do={
  :put $i
  :set i ($i + 1)
}
```

**Do-while** (body executes at least once):

```rsc
:local i 0
:do {
  :put $i
  :set i ($i + 1)
} while ($i < 10)
```

### 6.5 Function Definition

RouterOS has no `:function` keyword. Functions are simulated using `:global`
variable with a `do={}` block:

```rsc
# Define a function
:global myFunc do={
  :local a $1      # first argument
  :local b $2      # second argument
  :local sum ($a + $b)
  :return $sum
}

# Call it
:global myFunc     # re-declare in scope
:local result [$myFunc 3 4]   # result = 7
```

**Argument passing:**
- Arguments are positional: `$1`, `$2`, ... `$9` for first nine.
- Beyond 9: use `$10`, `$11`, etc. (but limited by the parser).
- No named parameters, no default values.
- A function that doesn't `:return` returns `nothing`.

**Nested function pattern:**

```rsc
:global outer do={
  :local inner do={
    :put "inside $1"
  }
  [$inner $1]
}

:global outer
[$outer "test"]   # output: "inside test"
```

**Recursive function:**

```rsc
:global factorial do={
  :if ($1 <= 1) do={
    :return 1
  }
  :return ($1 * [$factorial ($1 - 1)])
}

:global factorial
:put [$factorial 5]   # 120
```

### 6.6 Array Operations

**Access elements:**

```rsc
:local arr {a; b; c}
:put [$arr->0]       # a
:put [$arr->($idx)]  # dynamic index
```

**Set element:**

```rsc
:set ($arr->1) "z"   # arr is now {a; z; c}
```

**Append:**

```rsc
:set arr ($arr, "d")   # arr is now {a; b; c; d}
```

**Array with named keys (map/dict):**

```rsc
:local user {name="admin"; group="full"; disabled=no}
:put ($user->"name")    # admin
:set ($user->"group") "read"
```

**2D arrays:**

```rsc
:local matrix {{1;2}; {3;4}}
:put [$matrix->0->1]    # 2
```

**Array length:**

```rsc
:put [:len $arr]
```

**Find in array:**

```rsc
:local idx [:find $arr "b"]   # first index of "b", or -1
```

## 7. Export/Import Format

### 7.1 Export File Header Structure

A standard RouterOS `/export` file begins with a header:

```rsc
# jan/02/2026 14:30:00 by RouterOS 7.16
# software id = ABCD-1234
#
#
/interface bridge
add name=bridge1
/ip address
add address=10.0.0.1/24 interface=bridge1 network=10.0.0.0
...
```

**Header components:**

| Line                      | Description                              |
|---------------------------|------------------------------------------|
| `# date time by RouterOS version` | Export timestamp and RouterOS version |
| `# software id = XXXX-XXXX` | Software/device license ID            |
| `# model = CCR1036-8G-2S+` | Device model (if exported from device)|
| `#` (blank)               | Separator                                |

The header is informational. All commands after the header lines are valid
importable syntax.

### 7.2 Export Parameters

```rsc
/export compact           # default — omits default values
/export verbose           # includes all values, including defaults
/export hide-sensitive    # masks passwords, keys, secrets
/export show-sensitive    # reveals sensitive values (v7.14+, use with caution)
```

**Note:** `terse` is **NOT** a valid `/export` parameter in RouterOS v7. It was a v6-only parameter. Use `/print terse` for compact per-menu output instead.

| Mode            | v7  | v6  | Default values | Default items | Readability |
|-----------------|-----|-----|---------------|---------------|-------------|
| `compact=yes`   | ✓   | ✓   | Omitted       | Omitted       | Good        |
| `verbose=yes`   | ✓   | ✓   | Included      | Included      | Verbose     |
| `hide-sensitive`| ✓   | ✓   | Omitted       | Omitted       | Good        |
| `show-sensitive`| ✓   | ✗   | Omitted       | Omitted       | Good        |

**Validation impact:**
- **Compact mode** is harder to audit because omitted values are implicit defaults.
  The auditor must know what the default is for each parameter.
- **Verbose mode** is preferred for audit — every parameter is explicitly stated.
- **show-sensitive=yes** (v7.14+) reveals passwords and keys in the export. Use with
  extreme caution — never distribute show-sensitive exports. Audit scripts should
  flag this as a data-exposure risk if seen in shared configs.
- The audit check should flag when compact mode is used on a compliance-sensitive
  config.

### 7.3 Hide-Sensitive Behavior

```rsc
/export hide-sensitive       # masks passwords, keys, secrets
/export hide-sensitive file=backup   # with file output
```

**Values masked:**
- User passwords → `******`
- PPP secrets → `******`
- BGP MD5 keys → `******`
- IPSec PSK → `******`
- WiFi passphrases → `******`
- SNMP community strings → `******`
- RADIUS secrets → `******`
- RouterOS license keys → `******`

**Validation impact:**
- When a value shows `******`, the audit cannot verify strength, uniqueness, or
  that it differs from defaults.
- The presence of `******` must be noted as "indeterminate" in audit findings
  rather than "pass" or "fail".

#### show-sensitive=yes (v7.14+)

```rsc
/export show-sensitive       # reveals all passwords, keys, secrets in plaintext
```

**Introduced in:** RouterOS v7.14
**Warning:** This is the inverse of `hide-sensitive`. It outputs ALL sensitive values
in plaintext. Never: (a) distribute show-sensitive exports, (b) store them in
unencrypted locations, (c) leave them in public or shared directories.

**Audit implications:**
- If a config was exported with `show-sensitive=yes`, password/secrets can be
  fully audited for strength.
- The presence of `show-sensitive=yes` in the export header is itself a finding
  (indicates the export was created without security awareness).
- Flag in audit as "informational — show-sensitive export used, sensitive data
  visible in plaintext".

### 7.4 What Export Does NOT Include

| Item                           | Reason                                           |
|--------------------------------|--------------------------------------------------|
| Dynamic/learned routes         | Runtime state, not configuration                 |
| DHCP leases (dynamic)          | Runtime state                                    |
| ARP table entries              | Runtime state                                    |
| Connection tracking state      | Runtime state                                    |
| Queue tree stats               | Runtime state                                    |
| Installed certificates         | Binary, not exportable; use `/certificate export`|
| User manager database          | Separate subsystem                               |
| Caps-man remote AP configs     | Provisioned separately                           |
| The Dude configurations        | Separate application                             |
| Cloud DNS dynamic record       | Runtime state                                    |

### 7.5 System Default Entries — RouterOS v7.22

Exported configs do not include items that are "default" unless `verbose=yes`
is used. The following default entries exist on a fresh RouterOS v7.22 installation.

> **Note:** Default rules may vary by device model and RouterOS version. The
> `default-configuration` feature (v7.10+) generates rules dynamically based on
> device configuration. Use `/export verbose=yes` to see actual defaults on a
> specific device.

**Default firewall filter rules (IPv4):**

| Chain     | Action   | Condition                                           | Note                        |
|-----------|----------|-----------------------------------------------------|-----------------------------|
| input     | accept   | connection-state=established,related                 | Allow return traffic        |
| input     | drop     | in-interface-list=!LAN                               | Block non-LAN input         |
| input     | accept   | protocol=icmp                                        | Allow ICMP (limited)        |
| forward   | accept   | connection-state=established,related                 | Allow return traffic        |
| forward   | drop     | connection-state=invalid                             | Drop invalid packets        |
| forward   | accept   | out-interface-list=WAN                               | Allow WAN-bound traffic     |
| forward   | drop     | in-interface-list=!LAN                               | Block non-LAN forwarding    |
| forward   | fasttrack| connection-state=established,related                 | FastTrack acceleration      |

**Default address-lists (defconf):**

| Name      | Address                    | Purpose                    |
|-----------|----------------------------|----------------------------|
| WAN       | <wan-interface>            | WAN-facing interfaces      |
| LAN       | <lan-bridge>               | LAN-facing interfaces      |

**Default services (enabled by default in v7.22 fresh install):**

| Service   | Port  | Default Status |
|-----------|-------|----------------|
| ssh       | 22    | enabled        |
| winbox    | 8291  | enabled        |
| api       | 8728  | enabled        |
| api-ssl   | 8729  | disabled       |
| www       | 80    | enabled (redirect to 443 on hAP) |
| www-ssl   | 443   | enabled        |
| telnet    | 23    | **disabled**   |
| ftp       | 21    | **disabled**   |

### 7.6 Import Best Practices

1. **Always use `dry-run=yes` first** (v7.16+):
   ```rsc
   /import file=config.rsc dry-run=yes verbose=yes
   ```

2. **Use `verbose=yes` during import** to see every command applied.

3. **Use `from-line=N` for resume after failure:**
   ```rsc
   /import file=config.rsc from-line=342
   ```

4. **Remove the export header** (`# date time by...`) before importing if the
   header causes issues — though RouterOS v7 skips header lines during import.

5. **Verify the version matches:** Importing a v7 export into v6 will fail on
   many commands. Importing v6 into v7 often works but may miss some parameters.

6. **Sensitive values** in imports: if `hide-sensitive` was used, the import
   will set passwords to `******` literally, which will break authentication.
   Always supply real values when importing.

## 8. Common Syntax Errors

### 8.1 Numeric ID Usage (`*1`, `*2` Instead of `find`)

**Wrong:**
```rsc
/ip firewall filter set *1 disabled=yes
```

**Why it's wrong:** Hardcoded IDs (`*1`, `*FFF2`) are assigned at runtime and
change when items are added or removed. An export from one device applied to
another will have completely different IDs.

**Correct:**
```rsc
/ip firewall filter set [find where=comment="my-rule"] disabled=yes
# or with chaining:
/ip firewall filter set [find where=chain=input action=accept protocol=tcp dst-port=22] disabled=yes
```

### 8.2 Empty Array `{}` Syntax Error

**Wrong:**
```rsc
:local empty {}
```

**Error:** `syntax error: unexpected }` (or similar). The parser expects at least
one element or a semicolon inside `{}`.

**Correct:**
```rsc
:local empty [:toarray ""]
```

A workaround that also works (creates a single nil element, not truly empty):
```rsc
:local nearlyEmpty {:nothing}
```

The only reliable way to get zero-length arrays is `:toarray ""`.

### 8.3 Division Ambiguity (`10/2` Parsed as IP)

In RouterOS script, a bare `a/b` sequence with no spaces is preferentially parsed
as an IP address or IP prefix, **not** as division.

```rsc
:put (10/2)          # 10.0.0.2 — parsed as IP shorthand
:put (10 / 2)        # 5 — parsed as division
:put (192.168/16)    # 192.168.0.0/16 — parsed as IP prefix
```

**Always add spaces around `/` for division.** This is the #1 source of subtle
numeric bugs in RouterOS scripts.

### 8.4 String Concatenation with Arrays Using `.`

**Wrong:**
```rsc
:local list {a; b; c}
:put "items: " . $list    # "items: abc" — concatenates elements without separator
```

**Correct:**
```rsc
:put "items: $list"       # "items: a b c" — space-separated
:put "items: " . [:pick $list 0]  # "items: a" — single element
```

The `.` operator on arrays auto-converts to string by joining elements without a
separator. `$list` in interpolation joins with spaces. These are different.

### 8.5 Reserved Variable Name Conflicts

See §2.2. The most common real-world pitfalls:

```rsc
# WRONG — shadows 'type' parameter inside print
:local type "ether1"
/interface print where type=$type   # is this comparing the column 'type' or the local?
```

```rsc
# WRONG — 'name' as local inside a /user block
:local name "admin"
/user set [find where=name=$name] password="new"  # local $name wins
```

### 8.6 Missing Backslash Continuation Rules

```rsc
# WRONG — trailing space after \ breaks continuation
/ip firewall filter add chain=input \
  protocol=tcp dst-port=22 \ 
  action=accept

# WRONG — comment after \ also breaks
/ip firewall filter add chain=input \
  protocol=tcp dst-port=22 \# allow SSH
  action=accept
```

In both cases, the `\` is not the last character, so continuation does not apply.
The line is parsed as though the `\` was a regular token, causing a parse error.

### 8.7 Missing Line Termination in Blocks

```rsc
:if ($x > 0) do={
  :put "positive"
  :put "really positive"   # ← no semicolon needed here — newline is terminator
  :put "still fine"
}
```

Newlines inside `{}` are statement terminators, so `;` is optional. However,
when putting multiple statements on one line inside a block:

```rsc
:if ($x > 0) do={ :put "a" :put "b" }    # WRONG — parse error
:if ($x > 0) do={ :put "a"; :put "b" }   # CORRECT — ; separates them
```

### 8.8 Parameter Value with Spaces (Not Quoted)

**Wrong:**
```rsc
/ip firewall filter add chain=input comment=allow SSH from office
```

This adds a rule with `comment=allow` and then fails on `SSH` as an unknown token.

**Correct:**
```rsc
/ip firewall filter add chain=input comment="allow SSH from office"
```

**Rule:** Any parameter value containing spaces, `;`, `#`, `=`, or `[` must be
in double quotes.

### 8.9 Case Sensitivity in Paths

**Menu paths are case-insensitive** in RouterOS:

```rsc
/IP/Firewall/Filter add chain=input action=drop     # works
/ip firewall filter add chain=input action=drop     # works
```

**Parameter names are case-insensitive:**

```rsc
/ip firewall filter add CHAIN=input ACTION=drop     # works
```

**Parameter values are generally case-sensitive** (exceptions exist):

```rsc
/ip firewall filter add chain=input action=drop     # 'drop' must be lowercase
/ip firewall filter add chain=input action=DROP     # ERROR — invalid action
/ip service set telnet disabled=yes                 # 'yes' must be lowercase
```

### 8.10 Other Common Errors

| Error Pattern                                    | Explanation                                        |
|--------------------------------------------------|----------------------------------------------------|
| `$1` in non-function context                     | Positional args only work inside `do={}` blocks    |
| `:return` outside a function                     | `:return` is only valid inside a `do={}` block     |
| `:break` / `:continue` outside a loop            | Causes "break outside loop" error                  |
| Missing `do={}` on `:if` or `:for`              | `:if ($x) :put "x"` is syntax error               |
| `/int print` instead of `/interface print`       | Abbreviated paths may be ambiguous                 |
| `:set var` without value                         | Unsets var? No — causes error; use `:undefine`     |
| Forgetting `:global` in function body             | Without re-declaration, the global is not in scope |

## 9. RouterOS v6 vs v7 Differences

### 9.1 BGP Redesign

| Aspect          | RouterOS v6                                  | RouterOS v7                                  |
|-----------------|----------------------------------------------|----------------------------------------------|
| Config model    | `/routing bgp instance` + `/routing bgp peer` | `/routing bgp template` + `/routing bgp connection` |
| AS management   | Per-instance                                 | Per-connection with template inheritance     |
| Multiprotocol   | Limited                                      | Built-in per-address-family                  |
| Templates       | Not supported                                | Full template hierarchy                      |

**v6 syntax:**
```rsc
/routing bgp instance set default as=64512 router-id=10.0.0.1
/routing bgp peer add instance=default remote-address=10.0.1.1 remote-as=64513
```

**v7 syntax:**
```rsc
/routing bgp template set default as=64512 router-id=10.0.0.1
/routing bgp connection add name=peer1 remote.address=10.0.1.1 remote.as=64513 templates=default
```

### 9.2 OSPF Changes

| Aspect             | RouterOS v6                      | RouterOS v7                              |
|--------------------|----------------------------------|------------------------------------------|
| Interface config   | Per-interface under `/routing ospf interface` | `/routing ospf interface-template` |
| Area assignment    | Per-interface                    | Per-template with network matching       |
| Instance type      | `/routing ospf instance`         | `/routing ospf instance` (renamed fields)|
| Default originate  | `redistribute-default-route=always` | `default-originate=always`           |

**v6 syntax:**
```rsc
/routing ospf interface add interface=ether1 area=backbone
/routing ospf instance set default router-id=10.0.0.1
```

**v7 syntax:**
```rsc
/routing ospf interface-template add networks=10.0.0.0/24 area=backbone
/routing ospf instance set default router-id=10.0.0.1
```

### 9.3 Routing Tables

In v6, routing tables existed implicitly. In v7, they must be **created explicitly**
before use:

```rsc
/routing table add name=mytable fib
/ip route add dst-address=10.0.0.0/24 gateway=10.0.1.1 routing-table=mytable
```

The `fib` flag creates the Forwarding Information Base entry. Without it, the
table exists as a named reference but routes are not installed.

### 9.4 Routing Filter Syntax

v6 and v7 use completely different routing filter syntaxes.

**v6** (proplist-based):
```rsc
/routing filter add chain=BGP-IN prefix=10.0.0.0/8 action=accept
/routing filter add chain=BGP-IN prefix=192.168.0.0/16 action=reject
```

**v7** (script-like, Bolt language-inspired):
```rsc
/routing filter rule
add chain=BGP-IN disabled=no rule="if (dst in 10.0.0.0/8) { accept }"
add chain=BGP-IN disabled=no rule="if (dst in 192.168.0.0/16) { reject }"
```

v7 filters are stored as strings in the `rule` property and use a custom filter
language (`if`, `set`, `accept`, `reject`, `community`, `bgp-prepend`, etc.).

### 9.5 WiFi Split

| Aspect        | RouterOS v6                          | RouterOS v7                         |
|---------------|--------------------------------------|-------------------------------------|
| Interfaces    | `/interface wireless` (legacy)       | `/interface wifi` (Wave2)           |
| CAPsMAN       | `/caps-man`                          | `/interface wifi capsman`           |
| Configuration | `/interface wireless security-profile` | `/interface wifi configuration`   |
| Encryption    | `authentication-type` + `encryption` | `security` object with WPA3 support |
| Channel       | `frequency` + `band`                 | `channel` object with `frequency`   |

#### Driver Packages

v7 splits WiFi support into three driver packages for different hardware:

| Package             | Hardware Target                    | Status                     |
|---------------------|------------------------------------|----------------------------|
| `wifi-qcom-ac`      | Qualcomm IPQ4019 (hAP ac², RB4011) | **Stable**, recommended    |
| `wifi-qcom`         | Qualcomm IPQ8074 (hAP ax³, CCR2000)| **Stable**, v7.13+         |
| `wifi-qcom-legacy`  | Older Qualcomm (RB922, SXTsq)      | Legacy support             |
| `wireless` (legacy) | All Atheros/Mediatek (pre-v7)      | **Removed** in v7.14+      |

**Deprecation timeline:**
- RouterOS v7.0–v7.13: Both `wireless` (legacy) and `wifi-*` (Wave2) coexist
- RouterOS v7.14+: `wireless` package removed — only `wifi-*` drivers available
- RouterOS v7.15+: Channel auto-selection (`frequency=auto`), `skip-dfs-channels=` added

**v6 syntax:**
```rsc
/interface wireless set wlan1 mode=ap-band=2ghz-b/g/n frequency=2412
/interface wireless security-profile set default authentication-type=wpa2-psk
```

**v7 syntax:**
```rsc
/interface wifi set wlan1 configuration=cfg1 channel=freq1
/interface wifi configuration add name=cfg1 security=sec1 ssid=MyNet
/interface wifi security add name=sec1 authentication-types=wpa2-psk
/interface wifi channel add name=freq1 frequency=2412 width=20
```

**Note:** v7 retains backward compatibility only until v7.13. Devices upgraded to
v7.14+ with legacy wireless configs will have their WiFi interfaces disabled until
migrated to `/interface wifi`. Always check the `wifi-qcom-ac` or `wifi-qcom`
package is installed on v7.14+.

### 9.6 Import Dry-Run (v7.16+)

v7.16 introduced `dry-run=yes` for `/import`. This is a critical audit feature:

```rsc
/import file=config.rsc dry-run=yes verbose=yes
```

Dry-run validates syntax, dependencies, and would-apply state without modifying
the running configuration. v6 has no equivalent — imports are always
apply-immediately.

### 9.7 REST API

v7 introduced a built-in REST API. This is relevant for .rsc auditing because
the REST API may be enabled as an additional attack surface:

```rsc
/ip/service set www-ssl disabled=no port=443
```

The REST API uses the `www-ssl` service on port 443 (or `www` on 80). In v6,
there is no REST API — only the API service (port 8728/8729).

### 9.8 Other Notable Differences

| Feature                   | v6                             | v7                              |
|---------------------------|--------------------------------|---------------------------------|
| Container support         | ❌                             | ✅ `/container`                |
| WireGuard                 | ✅ basic                       | ✅ full, `/interface wireguard`|
| `:serialize`/`:deserialize` | ❌                          | ✅ (JSON support)              |
| `:retry`                  | ❌                             | ✅                              |
| `:onerror`                | ❌                             | ✅                              |
| `:undefine`               | ❌                             | ✅                              |
| `/tool/rommon`            | N/A                            | ✅                              |
| IPv6 firewall             | `/ipv6 firewall` (basic)       | `/ipv6 firewall` (extended)     |
| `:while` / `:do-while`   | ✅                             | ✅                              |
| `:range`                  | ✅                             | ✅                              |

## 10. Idempotent Pattern Validation Rules

Idempotent scripts produce the same result regardless of how many times they are
run. Non-idempotent scripts create duplicate rules, duplicate address-list entries,
and duplicate routes on every execution. These patterns are critical for
scheduler scripts and auto-configuration.

### 10.1 Using `[find]` Instead of Hardcoded IDs

**Non-idempotent (dangerous):**
```rsc
/ip firewall filter set *1 disabled=yes
```

**Idempotent:**
```rsc
/ip firewall filter set [find where=comment="my-rule"] disabled=yes
```

**Audit rule:** Any `set`, `remove`, `enable`, `disable` with a bare `*` ID
should flag a warning. The only exception is immediately after an `add` command
that returns the new ID.

### 10.2 Guard Pattern: Check Before Add

**Non-idempotent:**
```rsc
/ip firewall address-list add address=10.0.0.1 list=allowed
```

Running this twice creates two identical list entries.

**Idempotent guard:**
```rsc
:if ([:len [/ip firewall address-list find where=address=10.0.0.1 list=allowed]] = 0) do={
  /ip firewall address-list add address=10.0.0.1 list=allowed
}
```

**Shorthand (uses short-circuit):**
```rsc
:if ([/ip firewall address-list find where=address=10.0.0.1 list=allowed] = {}) do={
  /ip firewall address-list add address=10.0.0.1 list=allowed
}
```

**Audit rule:** `add` commands in scheduler scripts or function bodies should be
preceded by a `:if` guard using `find`. Especially for: address-list, routes,
NAT rules, filter rules, DHCP leases, DNS static records.

### 10.3 `:onerror` Wrapping for Error Handling

RouterOS v7+ `:onerror` provides idempotent error recovery:

```rsc
:onerror err in={
  /ip route add dst-address=10.0.0.0/24 gateway=10.0.1.1
} do={
  :log error ("route add failed: " . $err)
}
```

**Audit rule:** Critical configuration commands (routes, firewall rules, user
changes) should be wrapped in `:onerror` to prevent partial configuration
from aborting a script midway. Lack of error handling in automated scripts
should be flagged.

### 10.4 `:jobname` for Single-Instance Execution

Scheduler scripts can be triggered while a previous instance is still running.
`:jobname` can enforce single-instance:

```rsc
:local jobname "my-config-sync"
:if ([:len [/system script job find where=jobname=$jobname]] > 1) do={
  :log warning "instance already running, exiting"
  :error "duplicate instance"
}
```

**Audit rule:** Long-running scheduler scripts (sync jobs, config backups, health
checks) should use single-instance guards. Missing guards should be flagged at
Medium severity.

### 10.5 `:print as-value` for Robust Parameter Extraction

Instead of fragile text parsing of `print` output, use `as-value` for structure:

**Fragile (text parsing):**
```rsc
:local interface [/ip dhcp-client print as-value where=.id=*1 ]
:local status $interface->"status"
```

**Robust:**
```rsc
:local clientStatus [/ip dhcp-client get [find where=interface=ether1] status]
```

**Audit rule:** Prefer `get` with `[find]` or `print as-value` over line-by-line
text parsing. Detected use of `:execute` with a print command piped through
string operations should be flagged for replacement.

### 10.6 Idempotency Decision Matrix

| Operation          | Idempotent? | Notes                                       |
|--------------------|-------------|---------------------------------------------|
| `add`              | ❌          | Always creates a new item                   |
| `set` with `[find]`| ✅          | Modifies existing item by match             |
| `set` with `*N`    | ✅ (once)   | Breaks on re-import (IDs differ)           |
| `remove` with `[find]` | ✅     | Removes matching items, safe on re-run      |
| `/ip route add`    | ❌          | Same prefix/gateway creates duplicate       |
| `/ip route set`    | ✅          | Modify existing by `[find]`                |
| `/file remove`     | ✅          | No-op if file doesn't exist? No — error     |
| `:global` set      | ✅          | Same value re-assigned is harmless          |

### 10.7 Common Non-Idempotent Anti-Patterns

| Anti-pattern                                       | Why it's bad                              |
|----------------------------------------------------|-------------------------------------------|
| `add` without `:if [find]` guard                   | Duplicates on re-run                      |
| `set *1` in schedule script                        | ID changes after any add/remove           |
| `/file remove [find]` in auto-cleanup without `:len` check | Error on missing file         |
| Multiple `enable` calls on same item               | Harmless but noisy                        |
| Repeated `:global var=value` without checking      | Works but may overwrite persisted values   |
| `/user add` without guard                          | Duplicate users on re-run                  |

## 11. Path Reference

Common configuration menu paths organized by category.

### 11.1 Interfaces

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/interface`                          | All interfaces                     |
| `/interface bridge`                   | Bridge interfaces                  |
| `/interface bridge port`              | Bridge port members                 |
| `/interface bridge vlan`              | Bridge VLAN filtering               |
| `/interface bridge settings`          | Bridge global settings              |
| `/interface ethernet`                 | Ethernet interfaces                 |
| `/interface bonding`                  | Bonding (LAG) interfaces            |
| `/interface vlan`                     | VLAN interfaces                     |
| `/interface vrrp`                     | VRRP redundancy                     |
| `/interface pptp-server`              | PPTP server interfaces              |
| `/interface ovpn-server`              | OpenVPN server interfaces           |
| `/interface l2tp-server`              | L2TP server interfaces              |
| `/interface sstp-server`              | SSTP server interfaces              |
| `/interface wireless`                 | Wireless interfaces (v6)            |
| `/interface wifi`                     | WiFi interfaces (v7 Wave2)          |
| `/interface wifi configuration`       | WiFi config profiles (v7)           |
| `/interface wifi security`            | WiFi security profiles (v7)         |
| `/interface wifi channel`             | WiFi channel plans (v7)             |
| `/interface wifi capsman`             | CAPsMAN management (v7)             |
| `/interface wifi provisioning`        | CAP provisioning (v7)               |
| `/interface wireguard`                | WireGuard interfaces                |
| `/interface wireguard peers`          | WireGuard peer configuration        |
| `/interface gre`                      | GRE tunnels                         |
| `/interface eoip`                     | EoIP tunnels                        |
| `/interface ipip`                     | IP-IP tunnels                       |
| `/interface 6to4`                     | 6to4 tunneling                      |
| `/interface veth`                     | Virtual Ethernet (container)        |
| `/interface macvlan`                  | MAC VLAN interfaces                 |
| `/interface dot1x`                    | 802.1X port authentication          |
| `/interface zerotier`                 | ZeroTier virtual network            |
| `/interface list`                     | Interface lists                     |
| `/interface list member`              | Interface list members               |

### 11.2 IP

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/ip address`                         | IP addresses on interfaces         |
| `/ip route`                           | Static routes                       |
| `/ip route rule`                      | Routing policy rules                |
| `/ip firewall filter`                 | Firewall filter rules               |
| `/ip firewall nat`                    | NAT rules                           |
| `/ip firewall mangle`                 | Mangle rules                        |
| `/ip firewall raw`                    | Raw (early-stage) firewall rules    |
| `/ip firewall address-list`           | Address lists                       |
| `/ip firewall layer7-protocol`        | Layer-7 protocol definitions        |
| `/ip firewall connection`             | Connection tracking                 |
| `/ip firewall connection tracking`    | Connection tracking settings        |
| `/ip dhcp-server`                     | DHCP server                         |
| `/ip dhcp-server network`             | DHCP server networks                |
| `/ip dhcp-server lease`               | DHCP server leases                  |
| `/ip dhcp-client`                     | DHCP client on interfaces           |
| `/ip dhcp-relay`                      | DHCP relay                          |
| `/ip dns`                             | DNS server settings                 |
| `/ip dns static`                      | Static DNS entries                  |
| `/ip neighbor`                        | Neighbor discovery                  |
| `/ip neighbor discovery-settings`     | Neighbor discovery settings         |
| `/ip pool`                            | IP pools                            |
| `/ip arp`                             | ARP table entries                   |
| `/ip accounting`                      | IP accounting                       |
| `/ip cloud`                           | MikroTik Cloud (DDNS)               |
| `/ip service`                         | Service settings (ssh, www, api)    |
| `/ip hotspot`                         | Hotspot configuration               |
| `/ip socks`                           | SOCKS proxy                         |
| `/ip traffic-flow`                    | Traffic flow (netflow)             |
| `/ip settings`                        | Global IP settings                  |
| `/ip ssh`                             | SSH server settings                 |
| `/ip firewall service-port`           | Service port (helper) settings      |

### 11.3 IPv6

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/ipv6 address`                       | IPv6 addresses                      |
| `/ipv6 route`                         | IPv6 static routes                  |
| `/ipv6 firewall filter`               | IPv6 firewall filter                |
| `/ipv6 firewall address-list`         | IPv6 address lists                  |
| `/ipv6 nd`                            | Neighbor discovery                  |
| `/ipv6 dhcp-client`                   | IPv6 DHCP client                    |
| `/ipv6 dhcp-server`                   | IPv6 DHCP server                    |
| `/ipv6 dhcp-relay`                    | IPv6 DHCP relay                     |
| `/ipv6 pool`                          | IPv6 pools                          |
| `/ipv6 settings`                      | Global IPv6 settings                |

### 11.4 Routing

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/routing bgp instance`               | BGP instance (v6)                  |
| `/routing bgp peer`                   | BGP peer (v6)                      |
| `/routing bgp template`               | BGP template (v7)                  |
| `/routing bgp connection`             | BGP connection (v7)                |
| `/routing bgp session`                | BGP session status                 |
| `/routing bgp network`                | BGP network advertisement          |
| `/routing bgp aggregate`              | BGP route aggregation              |
| `/routing ospf instance`              | OSPF instance                      |
| `/routing ospf interface`             | OSPF interface (v6)                |
| `/routing ospf interface-template`    | OSPF interface template (v7)       |
| `/routing ospf area`                  | OSPF area                          |
| `/routing ospf lsa`                   | OSPF link-state advertisements      |
| `/routing filter`                     | Routing filter (v6)                |
| `/routing filter rule`                | Routing filter rules (v7)          |
| `/routing table`                      | Routing tables (v7)                |
| `/routing rule`                       | Routing policy rules               |
| `/routing id`                         | Router-ID configuration            |
| `/routing bfd`                        | BFD (Bidirectional Forwarding Detection) |

### 11.5 System

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/system identity`                    | Router hostname                    |
| `/system clock`                       | System time/date                   |
| `/system ntp client`                  | NTP client settings                |
| `/system ntp server`                  | NTP server settings                |
| `/system logging`                     | System log rules                   |
| `/system logging action`              | Logging targets                    |
| `/system script`                      | Scripts                            |
| `/system script job`                  | Running script jobs                |
| `/system scheduler`                   | Scheduler (cron)                   |
| `/system backup`                      | System backup                      |
| `/system resource`                    | Resource monitoring (read-only)    |
| `/system routerboard`                 | RouterBOOT settings                |
| `/system routerboard settings`        | RouterBOOT settings                |
| `/system note`                        | System note                        |
| `/system package`                     | Package management (v6)            |
| `/system package update`              | Update channel (v6)                |
| `/system health`                      | Hardware sensors                   |
| `/system watchdog`                    | Watchdog settings                  |
| `/system ntp`                         | NTP settings (v7 combined)         |
| `/container`                          | Container management                |
| `/container mounts`                   | Container mount points              |
| `/container envs`                     | Container environment variables     |

### 11.6 User Management

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/user`                               | Local user accounts                |
| `/user group`                         | User groups                        |
| `/user ssh-keys`                      | SSH public keys                    |
| `/user aaa`                           | AAA settings                       |
| `/password`                           | Change current user's password     |

### 11.7 Certificates

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/certificate`                        | Certificate management             |
| `/certificate settings`               | Certificate settings               |
| `/certificate ca`                     | Certificate authority management    |
| `/certificate crl`                    | Certificate revocation lists        |

### 11.8 Files

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/file`                               | File system (disk)                  |

### 11.9 PPP & Tunnels

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/ppp profile`                        | PPP profiles                      |
| `/ppp secret`                         | PPP users/passwords               |
| `/ppp active`                         | Active PPP connections            |
| `/interface pppoe-client`             | PPPoE client                      |
| `/interface pppoe-server`             | PPPoE server                      |
| `/interface pptp-server`              | PPTP server                       |
| `/interface l2tp-server`              | L2TP server                       |
| `/interface sstp-server`              | SSTP server                       |
| `/interface ovpn-server`              | OpenVPN server                    |

### 11.10 SNMP

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/snmp`                               | SNMP agent settings               |
| `/snmp community`                     | SNMP communities                  |

### 11.11 Tools

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/tool bandwidth-server`              | Bandwidth test server              |
| `/tool mac-server`                    | MAC Telnet server                  |
| `/tool mac-server mac-winbox`         | MAC WinBox server                  |
| `/tool sniffer`                       | Packet sniffer                     |
| `/tool bandwidth-test`                | Bandwidth test server              |
| `/tool mac-server ping`               | MAC Ping server                    |
| `/tool sms`                           | SMS gateway                        |
| `/tool e-mail`                        | Email settings                     |
| `/tool graphing`                      | Graphing configuration             |
| `/tool traffic-monitor`               | Traffic monitoring                 |
| `/tool netwatch`                      | Network watchdog                   |
| `/tool rommon`                        | RouterBOOT access (v7)             |
| `/tool fetch`                         | HTTP/FTP file fetcher              |

### 11.12 Queue

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/queue simple`                       | Simple queues                     |
| `/queue tree`                         | Tree queues                        |
| `/queue type`                         | Queue types (PCQ, RED, etc.)       |

### 11.13 CAPsMAN
| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/caps-man manager`                   | CAPsMAN manager (v6)               |
| `/caps-man manager interface`         | CAPsMAN binding interfaces (v6)     |
| `/caps-man configuration`             | CAP config profiles (v6)            |
| `/caps-man security`                  | CAP security profiles (v6)          |
| `/caps-man channel`                   | CAP channel plans (v6)              |
| `/caps-man provisioning`              | CAP auto-provisioning (v6)          |
| `/caps-man access-list`              | CAP access rules (v6)               |
| `/caps-man aaa`                      | CAP RADIUS auth (v6)                |

### 11.14 Other

| Path                                  | Description                        |
|---------------------------------------|------------------------------------|
| `/container`                          | Container management (v7)          |
| `/disk`                               | Disk management                    |
| `/graphing`                           | Graphing (deprecated in v7)        |
| `/lcd`                                | LCD panel settings (hardware)      |
| `/log`                                | Log buffer (read-only)             |
| `/port`                               | Serial port settings               |
| `/radius`                             | RADIUS client settings             |
| `/romon`                              | RoMON management                   |
| `/special-login`                      | Special login (banner, etc.)       |
