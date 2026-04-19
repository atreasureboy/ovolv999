/**
 * Tool descriptions
 */

export const BASH_DESCRIPTION = `Executes a bash command and returns its output (stdout + stderr combined).

The working directory persists between calls via absolute paths. Shell state (variables, aliases) does NOT persist.

IMPORTANT: Avoid using this for file operations when dedicated tools exist:
- File search: Use Glob (NOT find or ls)
- Content search: Use Grep (NOT grep or rg)
- Read files: Use ReadFile (NOT cat/head/tail)
- Edit files: Use EditFile (NOT sed/awk)
- Write files: Use WriteFile (NOT echo > or cat <<EOF)

Reserve Bash for: security tools (nmap/nuclei/sqlmap/hydra/...), shell commands, scripts, system operations.

## Timeout Strategy (CRITICAL for security tools)

Default timeout: **300 seconds (5 min)**. Max: **14400 seconds (4 hours)**.

Always set an explicit timeout for security scans based on expected duration:
- Quick scans (top ports, single host): timeout=120000
- Standard scans (full ports, service detection): timeout=600000
- Deep scans (nuclei full, hydra brute): timeout=3600000
- Extended operations (nuclei -t all, large subnet): timeout=14400000

## Background Pattern for Long-Running Scans

For scans expected to run >5 minutes, ALWAYS use background mode to avoid blocking:

\`\`\`
# Step 1: Launch in background, redirect output to file
run_in_background=true
command: "nuclei -u https://target.com -o /tmp/nuclei_out.txt 2>&1"

# Step 2 (later): Check progress or read results
command: "tail -50 /tmp/nuclei_out.txt"

# Or wait for completion and read
command: "wait && cat /tmp/nuclei_out.txt"
\`\`\`

## Parallel Scanning

To run multiple scans simultaneously, call Bash multiple times with run_in_background=true in the SAME response.
All background jobs start simultaneously. Check results later by reading their output files.

Example: Launch nmap + nuclei + subfinder all at once:
- Call 1: nmap scan → /tmp/nmap.txt (background)
- Call 2: subfinder scan → /tmp/subs.txt (background)
- Call 3: httpx probe → /tmp/httpx.txt (background)
Then in next turn: read all three output files.

## Interactive Processes — CRITICAL WARNING

NEVER run interactive processes that wait for user input in a foreground Bash call.
These will block until timeout (30 min) and produce no useful output:

BLOCKED patterns:
- msfconsole without resource file (waits at "msf6 >" or "meterpreter >")
- nc / ncat without -l in a piped shell (blocks on stdin)
- python3 / irb / node REPL
- Any command that shows a "> " or "$ " prompt and waits for keystrokes

CORRECT pattern — use TmuxSession for ALL interactive processes:
  TmuxSession({ action: "new", session: "msf", command: "msfconsole -q" })
  TmuxSession({ action: "wait_for", session: "msf", pattern: "msf6 >", timeout: 60000 })
  TmuxSession({ action: "send", session: "msf", text: "use exploit/multi/handler" })
  TmuxSession({ action: "wait_for", session: "msf", pattern: "msf6.*>" })
  TmuxSession({ action: "send", session: "msf", text: "set LHOST 0.0.0.0" })
  TmuxSession({ action: "send", session: "msf", text: "set LPORT 4444" })
  TmuxSession({ action: "send", session: "msf", text: "run -j" })
  TmuxSession({ action: "wait_for", session: "msf", pattern: "session \\d+ opened", timeout: 120000 })

  Fallback (one-shot, no interaction needed): resource file + run_in_background
  Bash({ command: "msfconsole -q -r /tmp/msf.rc > /tmp/msf_out.txt 2>&1", run_in_background: true })
  KEY: "run -z" backgrounds session, "exit -y" forces exit.

## Other Instructions
- Always quote paths with spaces: "path with spaces/file.txt"
- Use absolute paths to avoid cwd confusion
- For dependent sequential commands, chain with && in one call`

export const READ_FILE_DESCRIPTION = `Reads a file from the filesystem and returns its contents with line numbers.

Usage:
- Provide an absolute file path
- Optionally specify offset (start line) and limit (number of lines) for large files
- Returns content in cat -n format: "line_number\\tcontent"
- Can read text files, code files, JSON, YAML, etc.`

export const WRITE_FILE_DESCRIPTION = `Writes content to a file, creating it if it doesn't exist or overwriting if it does.

IMPORTANT: For existing files, prefer EditFile (precise string replacement) over WriteFile (full overwrite).
Only use WriteFile for:
- Creating new files
- Complete rewrites where the entire content changes

Always read the file first before overwriting to avoid losing content.`

export const EDIT_FILE_DESCRIPTION = `Performs exact string replacement in a file.

Usage:
- Provide the file path, the exact string to find (old_string), and the replacement (new_string)
- The old_string must match EXACTLY including whitespace and indentation
- If old_string appears multiple times, use more context to make it unique
- Use replace_all=true to replace all occurrences

This is the preferred way to modify existing files — it's precise and shows exactly what changed.`

export const GLOB_DESCRIPTION = `Finds files matching a glob pattern, sorted by modification time (newest first).

Examples:
- "**/*.ts" — all TypeScript files recursively
- "src/**/*.{js,ts}" — JS/TS files under src/
- "*.json" — JSON files in current directory

Returns a list of matching absolute file paths.`

export const GREP_DESCRIPTION = `Searches file contents using regex patterns (powered by ripgrep).

Parameters:
- pattern: regex pattern to search for
- path: directory or file to search (defaults to cwd)
- glob: file pattern filter (e.g. "*.ts")
- output_mode: "files_with_matches" (default) | "content" | "count"
- context: lines before/after each match (when output_mode="content")
- case_insensitive: true/false

Examples:
- Find files containing "useEffect": pattern="useEffect", glob="*.tsx"
- Show matching lines: pattern="TODO", output_mode="content"
- Count matches: pattern="console.log", output_mode="count"`
