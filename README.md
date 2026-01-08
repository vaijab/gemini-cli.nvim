# gemini-cli.nvim

Gemini CLI integration with Neovim based on the [Gemini IDE Companion spec](https://github.com/google-gemini/gemini-cli/blob/main/docs/ide-integration/ide-companion-spec.md).

`gemini-cli.nvim` bridges the gap between your editor and the [Gemini CLI](https://github.com/google-gemini/gemini-cli) agent. It implements the **Model Context Protocol (MCP)** to give the AI agent deep, semantic access to your codebase using Neovim's own LSP and Tree-sitter capabilities.

## Features

### 🧠 Neovim as a Semantic Backend

This plugin transforms Neovim into a powerful backend for the AI. Instead of reading files as plain text, the agent leverages Neovim's internal understanding of code:

- **LSP-Powered Navigation:** The agent uses `Go to Definition`, `Find References`, and `Hover` types to explore code relationships accurately.
- **Smart Resolution:** The `resolveDefinition` tool combines LSP and Tree-sitter to locate a symbol and extract its **full implementation** (including docstrings) in a single step.
- **Tree-sitter Structure:** It can read file outlines and extract exact function implementations without guessing line numbers.
- **Semantic Search:** Finds symbols (classes, functions) directly, avoiding the noise of standard `grep`.
- **Diagnostics:** The agent can see errors and warnings in your project, allowing it to fix bugs proactively.

### ⚡ Gemini IDE Integration

- **Live Context Sync:** Automatically shares your open files, cursor position, and visual selections with the agent, so it always knows what you are working on.
- **Native Diff Workflow:** When the agent proposes code changes, they appear in a standard Neovim diff split.
- **Zero-Config:** The plugin automatically manages the MCP connection details, so the `gemini` CLI connects to your specific Neovim instance instantly.

## Requirements

- **Neovim** `>= 0.10`
- **Go** `>= 1.23` (required to build the internal bridge server)
- **Gemini CLI** installed globally: `npm install -g @google/gemini-cli`

## Quick Start

Install using [lazy.nvim](https://github.com/folke/lazy.nvim):

```lua
{
    "vaijab/gemini-cli.nvim",
    build = ":GeminiBuild", -- Essential: builds the Go server
    opts = {},
}
```

Once installed:

1. Open Neovim.
2. Run `gemini` in your terminal of choice.

**Recommended:** For the best experience, we recommend using [folke/sidekick.nvim](https://github.com/folke/sidekick.nvim) to run the agent in a dedicated sidebar directly within Neovim.

## Configuration

The `setup()` function accepts the following options:

```lua
require("gemini").setup({
    -- Enable verbose logging for debugging
    debug = false,
})
```

### Keymaps

The plugin provides commands for the diff workflow, but does not enforce default keymaps. You should set them up in your configuration:

```lua
-- Example keymaps
vim.keymap.set("n", "<leader>gy", "<cmd>GeminiDiffAccept<cr>", { desc = "Gemini Accept Diff" })
vim.keymap.set("n", "<leader>gn", "<cmd>GeminiDiffDeny<cr>",   { desc = "Gemini Reject Diff" })
```

## Available MCP Tools

These tools are exposed to the Gemini agent, allowing it to interact with Neovim's LSP and Tree-sitter engine:

- **`getWorkspaceStructure`**: Returns a directory tree. **Always used first** to understand the project layout without listing every single file.
- **`searchWorkspaceSymbol`**: Finds the exact definition location of a symbol (class, function, struct) by name. More precise than `grep`.
- **`resolveDefinition`**: The "Go To Definition" power tool. Locates a symbol and returns its **full implementation** (including docstrings) in one step.
- **`getReferences`**: Finds all usages of a symbol. Returns code snippets for every usage, acting as a "Semantic Grep".
- **`readSymbol`**: Reads the full implementation of a symbol by name. Safer than `read_file` because it guarantees getting the complete code block.
- **`getFileOutline`**: Generates a high-level table of contents (functions, classes, methods) for a file using Tree-sitter.
- **`getHover`**: Gets documentation and type signature for a symbol at a specific position.
- **`getDiagnostics`**: Retrieves errors and warnings for a file or the entire workspace.
- **`runTreesitterQuery`**: Runs a custom Tree-sitter query against a file to extract specific code sections.
