local M = {}
local tools = require("gemini.tools")

local job_id = nil
local session_port = nil
local session_token = nil
local last_opts = nil
local reconnect_timer = vim.loop.new_timer()
local success_timer = vim.loop.new_timer()
local reconnect_count = 0
local MAX_RECONNECT_ATTEMPTS = 5
local last_valid_buf = nil

-- Helper to get the default installation path
local function get_default_binary_path()
	return vim.fn.stdpath("data") .. "/gemini/gemini-server"
end

local function start_server()
	if not last_opts then
		return
	end

	local binary_path = last_opts.binary_path or get_default_binary_path()
	local log_path = last_opts.log_path or (vim.fn.stdpath("state") .. "/gemini.log")

	if job_id then
		vim.fn.jobstop(job_id)
		job_id = nil
	end

	-- Create state directory if it doesn't exist
	vim.fn.mkdir(vim.fn.fnamemodify(log_path, ":h"), "p")

	-- Check if binary exists before starting
	if vim.fn.executable(binary_path) == 0 then
		-- Silent return if binary is missing; user likely needs to build first.
		return
	end

	-- Start job WITH RPC (Stdio) and logging flag
	job_id = vim.fn.jobstart({
		binary_path,
		"--log-file",
		log_path,
		"--port",
		tostring(session_port),
		"--auth-token",
		session_token,
	}, {
		rpc = true,
		on_exit = function(jid, code)
			if jid ~= job_id then
				return
			end
			job_id = nil
			_G.gemini_job_id = nil
			if success_timer then
				success_timer:stop()
			end

			-- Code 143 is SIGTERM, usually from jobstop
			if code ~= 0 and code ~= 143 then
				if reconnect_count < MAX_RECONNECT_ATTEMPTS then
					reconnect_count = reconnect_count + 1
					local delay = math.min(1000 * math.pow(2, reconnect_count - 1), 10000)
					vim.notify(
						string.format(
							"[gemini] Server exited unexpectedly (code %d). Retrying in %dms (%d/%d)...",
							code,
							delay,
							reconnect_count,
							MAX_RECONNECT_ATTEMPTS
						),
						vim.log.levels.WARN
					)
					if reconnect_timer then
						reconnect_timer:stop()
						reconnect_timer:start(
							delay,
							0,
							vim.schedule_wrap(function()
								if not job_id then
									start_server()
								end
							end)
						)
					end
				else
					vim.notify(
						string.format(
							"[gemini] Server failed after %d attempts. Check logs at: %s",
							MAX_RECONNECT_ATTEMPTS,
							log_path
						),
						vim.log.levels.ERROR
					)
				end
			end
		end,
	})

	_G.gemini_job_id = job_id

	-- Notify server to initialize once it's connected
	if job_id > 0 then
		vim.rpcnotify(job_id, "initialize")
		if last_opts and last_opts.debug then
			vim.notify("Gemini: Server initialized", vim.log.levels.DEBUG)
		end
		-- Reset reconnect count if we stay alive for 10 seconds
		if success_timer then
			success_timer:stop()
			success_timer:start(
				10000,
				0,
				vim.schedule_wrap(function()
					reconnect_count = 0
				end)
			)
		end
	end
end

function M.build()
	local target_path = get_default_binary_path()
	local plugin_root = vim.fn.fnamemodify(debug.getinfo(1).source:sub(2), ":h:h:h")

	-- Ensure directory exists
	vim.fn.mkdir(vim.fn.fnamemodify(target_path, ":h"), "p")

	print("[gemini] Building server to: " .. target_path)

	local cmd = string.format(
		"go build -o %s ./cmd/gemini-server/main.go",
		vim.fn.shellescape(target_path)
	)

	vim.fn.jobstart(cmd, {
		cwd = plugin_root,
		on_exit = function(_, code)
			if code == 0 then
				print("[gemini] Server built successfully!")
			else
				print("[gemini] Build failed. Exit code: " .. code)
			end
		end,
		on_stderr = function(_, data)
			if data then
				for _, line in ipairs(data) do
					if line ~= "" then
						print("[gemini-build] " .. line)
					end
				end
			end
		end,
	})
end

function M.setup(opts)
	last_opts = opts or {}
	reconnect_count = 0

	if not session_port then
		math.randomseed(os.time())
		-- Use a port in the dynamic/private range (49152-65535)
		session_port = 49152 + math.random(0, 16380)
		session_token = string.format(
			"%04x%04x%04x%04x",
			math.random(0, 0xffff),
			math.random(0, 0xffff),
			math.random(0, 0xffff),
			math.random(0, 0xffff)
		)
	end

	local settings_path = vim.fn.stdpath("state") .. "/gemini/settings.json"
	local instructions_path = vim.fn.stdpath("state") .. "/gemini/gemini-nvim-instructions.md"
	local state_dir = vim.fn.fnamemodify(settings_path, ":h")
	
	vim.fn.mkdir(state_dir, "p")

	-- Write the semantic tool instructions
	local f_inst = io.open(instructions_path, "w")
	if f_inst then
		f_inst:write([[
# Gemini Neovim Integration Rules

You are an expert developer agent integrated into Neovim via the 'gemini-cli-nvim' MCP server.
Your environment has specialized SEMANTIC TOOLS that are significantly more efficient than standard file operations.

**CRITICAL TOOL USAGE RULES:**

1.  **Map First:** Always start new tasks with `getWorkspaceStructure` to understand the project layout.
2.  **Find Definitions:** Use `searchWorkspaceSymbol` to locate classes, functions, or types. Do NOT use `grep` for this.
3.  **Find Usages:** Use `getReferences`. It acts as a "Semantic Grep" and returns code snippets (context) for every match. You rarely need to open the file afterwards.
4.  **Inspect Code:** Use `readSymbol` to read implementations. It automatically extracts the full code block + docstrings. Avoid `read_file` for code inspection as it wastes tokens and risks line-number errors.
5.  **Go To Definition:** Use `resolveDefinition` when you see a symbol in code and want to jump to its source immediately.

**Workflow Examples:**

*   *Task:* "How does the User struct look?"
    *   *Bad:* `grep "struct User"` -> `read_file`
    *   *Good:* `searchWorkspaceSymbol "User"` -> `readSymbol "User"`

*   *Task:* "Where is runClient called?"
    *   *Bad:* `grep "runClient"` -> open 5 files to see context
    *   *Good:* `getReferences "runClient"` (provides context immediately)

Be efficient. Use the semantic tools.
]])
		f_inst:close()
	end

	local binary_path = last_opts.binary_path or get_default_binary_path()
	local url = string.format("http://127.0.0.1:%d/mcp?token=%s", session_port, session_token)

	local settings = {
		mcpServers = {
			["gemini-cli-nvim"] = {
				command = binary_path,
				args = { "client", url },
				excludeTools = { "openDiff", "closeDiff" },
			},
		},
		context = {
			fileName = { "GEMINI.md", "gemini-nvim-instructions.md" },
			includeDirectories = { state_dir },
			loadFromIncludeDirectories = true,
			loadMemoryFromIncludeDirectories = true,
		},
	}

	local f = io.open(settings_path, "w")

	if f then
		f:write(vim.json.encode(settings))
		f:close()
		vim.env.GEMINI_CLI_SYSTEM_SETTINGS_PATH = settings_path
	else
		print("[gemini] Failed to write settings file to: " .. settings_path)
	end

	vim.env.GEMINI_CLI_IDE_SERVER_PORT = tostring(session_port)
	vim.env.GEMINI_CLI_IDE_AUTH_TOKEN = session_token
	vim.env.GEMINI_CLI_IDE_WORKSPACE_PATH = vim.fn.getcwd()
	vim.env.TERM_PROGRAM = "vscode"

	if reconnect_timer then
		reconnect_timer:stop()
	end
	start_server()

	local group = vim.api.nvim_create_augroup("Gemini", { clear = true })

	local function send_context()
		if job_id and job_id > 0 then
			local current_buf = vim.api.nvim_get_current_buf()
			local buftype = vim.api.nvim_get_option_value("buftype", { buf = current_buf })

			if buftype ~= "" then
				return
			end

			last_valid_buf = current_buf

			local context = tools.get_context(last_valid_buf)
			vim.rpcnotify(job_id, "context_update", context)
			if last_opts and last_opts.debug then
				local active_file = nil
				for _, file in ipairs(context.workspaceState.openFiles) do
					if file.isActive then
						active_file = file
						break
					end
				end
				local msg = string.format("Gemini: Context updated (%d files)", #context.workspaceState.openFiles)
				if active_file then
					msg = msg .. string.format("\nActive: %s", vim.fn.fnamemodify(active_file.path, ":t"))
					if active_file.cursor then
						msg = msg .. string.format(" [%d:%d]", active_file.cursor.line, active_file.cursor.character)
					end
					if active_file.selectedText then
						msg = msg .. " (with selection)"
					end
				end
				vim.notify(msg, vim.log.levels.DEBUG)
			end
		end
	end

	local timer = vim.loop.new_timer()
	local function debounced_send_context()
		if timer then
			timer:stop()
			timer:start(50, 0, vim.schedule_wrap(send_context))
		end
	end

	vim.api.nvim_create_autocmd({ "BufEnter", "CursorMoved", "CursorMovedI", "FocusGained", "ModeChanged" }, {
		group = group,
		callback = debounced_send_context,
	})

	-- Define User Commands
	vim.api.nvim_create_user_command("GeminiBuild", function()
		M.build()
	end, {})

	vim.api.nvim_create_user_command("GeminiRestartServer", function()
		M.setup(opts)
		print("[gemini] Server restarted.")
	end, {})

	vim.api.nvim_create_user_command("GeminiStopServer", function()
		if reconnect_timer then
			reconnect_timer:stop()
		end
		if job_id then
			vim.fn.jobstop(job_id)
			job_id = nil
			print("[gemini] Server stopped.")
		end
	end, {})

	vim.api.nvim_create_user_command("GeminiDiffAccept", function()
		tools.diff_accept()
	end, {})

	vim.api.nvim_create_user_command("GeminiDiffDeny", function()
		tools.diff_deny()
	end, {})
end

return M
