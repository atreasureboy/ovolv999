/**
 * Tool description constants — used by tool definitions
 */

export const BASH_DESCRIPTION = 'Execute a bash command on the system. Use for compiling, running exploits, and system commands.'

export const READ_FILE_DESCRIPTION = 'Read the contents of a file at the given path.'

export const WRITE_FILE_DESCRIPTION = 'Write content to a file at the given path. Creates the file if it does not exist, overwrites if it does.'

export const EDIT_FILE_DESCRIPTION = 'Make precise edits to a file by replacing specific text.'

export const GLOB_DESCRIPTION = 'Find files matching a glob pattern.'

export const GREP_DESCRIPTION = 'Search for a regex pattern in file contents.'

export const TODO_DESCRIPTION = 'Create or update a task checklist to track progress.'

export const TMUX_SESSION_DESCRIPTION = 'Manage tmux sessions for long-running interactive processes (compilers, REPLs).'

export const SHELL_SESSION_DESCRIPTION = 'Manage reverse shell sessions — listen, execute, kill sessions.'

export const C2_DESCRIPTION = 'Command & Control interface for Metasploit/Sliver — deploy listeners and payloads.'

export const TECHNIQUE_GENERATOR_DESCRIPTION = 'Binary weaponization engine — compile evasion-aware payloads using Havoc/Sliver/APT28 techniques. Generates real compiled binaries with randomized fingerprints.'
