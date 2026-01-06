# gemini-cli.nvim

Seamless integration of the [Gemini CLI](https://github.com/google-gemini/gemini-cli) agent into Neovim using the Model Context Protocol (MCP).

This plugin allows the Gemini agent to "see" and "edit" your code using semantic tools (LSP, Tree-sitter) and provides a clean UI for reviewing proposed changes.

## Features

- **Semantic Awareness**: The agent uses LSP and Tree-sitter to understand code structure, find definitions, and locate usages accurately.
- **Context Sync**: Automatically shares your open files, cursor position, and selections with the agent.
- **Diff View**: Review agent-proposed changes in a native Neovim floating diff window.

## Prerequisites

- **Neovim** `>= 0.10`
- **Go** `>= 1.23` (to build the internal server)
- **Gemini CLI** installed (`npm install -g @google/gemini-cli`)

## Installation

Using [lazy.nvim](https://github.com/folke/lazy.nvim):

```lua
{
    "vaijab/gemini-cli.nvim",
    build = ":GeminiBuild",
    config = function()
        require("gemini").setup()
    end,
}
```

## Usage

1. **Start Neovim.** The plugin starts its background server automatically.
2. **Launch the Agent:**
    - **Recommended:** Use [folke/sidekick.nvim](https://github.com/folke/sidekick.nvim) for a dedicated sidebar and better window management.
    - **Manual:** Open a terminal in Neovim (`:term`) and run `gemini`.

The agent will automatically connect to Neovim and follow optimized semantic navigation rules.

### Diff Review

When the agent proposes a code change, a diff window will appear.

- **Accept:** `:GeminiDiffAccept` (or map to a key)
- **Reject:** `:GeminiDiffDeny` (or press `q` in the window)

## License

[LICENSE](LICENSE)
