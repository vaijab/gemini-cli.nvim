local M = {}

-- Store diff state: filePath -> { bufnr, ns_id, original_lines, new_content, job_id }
local diff_sessions = {}

function M.ensure_buffer(file_path)
	file_path = vim.fn.fnamemodify(file_path, ":p")
	local bufnr = vim.fn.bufnr(file_path, true)
	if not vim.api.nvim_buf_is_loaded(bufnr) then
		vim.fn.bufload(bufnr)
		-- Ensure filetype is set so LSP can attach
		if vim.api.nvim_get_option_value("filetype", { buf = bufnr }) == "" then
			vim.api.nvim_buf_call(bufnr, function()
				vim.cmd("filetype detect")
			end)
		end
	else
		-- If buffer is loaded and clean, sync with disk to avoid W12 warnings
		-- if the file was changed externally (e.g. by git or formatting tools)
		if not vim.api.nvim_get_option_value("modified", { buf = bufnr }) then
			vim.api.nvim_buf_call(bufnr, function()
				vim.cmd("silent! checktime")
			end)
		end
	end
	return bufnr
end

function M.open_diff(file_path, new_content)
	local job_id = _G.gemini_job_id
	file_path = vim.fn.fnamemodify(file_path, ":p")
	local bufnr = M.ensure_buffer(file_path)

	M.cleanup_session(file_path)

	-- Create scratch buffer for new content
	local scratch_buf = vim.api.nvim_create_buf(false, true)
	local new_lines = vim.split(new_content, "\n")
	vim.api.nvim_buf_set_lines(scratch_buf, 0, -1, false, new_lines)

	-- Match filetype and settings
	local ft = vim.api.nvim_get_option_value("filetype", { buf = bufnr })
	vim.api.nvim_set_option_value("filetype", ft, { buf = scratch_buf })
	vim.api.nvim_set_option_value("bufhidden", "wipe", { buf = scratch_buf })
	vim.api.nvim_buf_set_name(scratch_buf, "Gemini Diff: " .. vim.fn.fnamemodify(file_path, ":t"))

	-- Calculate Float Dimensions
	local uis = vim.api.nvim_list_uis()
	if #uis == 0 then
		return ""
	end
	local ui = uis[1]
	local width = math.floor(ui.width * 0.9)
	local height = math.floor(ui.height * 0.8)
	local row = math.floor((ui.height - height) / 2)
	local col = math.floor((ui.width - width) / 2)
	local half_width = math.floor(width / 2)

	-- Create Left Window (Original)
	local win_left = vim.api.nvim_open_win(bufnr, false, {
		relative = "editor",
		width = half_width,
		height = height,
		row = row,
		col = col,
		style = "minimal",
		border = "rounded",
		title = " Original ",
		title_pos = "center",
	})

	-- Create Right Window (New)
	local win_right = vim.api.nvim_open_win(scratch_buf, true, {
		relative = "editor",
		width = width - half_width,
		height = height,
		row = row,
		col = col + half_width,
		style = "minimal",
		border = "rounded",
		title = " Proposed Change ",
		title_pos = "center",
	})

	-- Setup Diff and Window Options
	local function setup_win(win)
		vim.api.nvim_win_call(win, function()
			vim.cmd("diffthis")
			vim.opt_local.number = true
			vim.opt_local.relativenumber = false
			vim.opt_local.cursorline = true
			vim.opt_local.wrap = false
		end)
	end
	setup_win(win_left)
	setup_win(win_right)

	-- Store session
	diff_sessions[file_path] = {
		bufnr = bufnr,
		scratch_buf = scratch_buf,
		win_left = win_left,
		win_right = win_right,
		new_content = new_content,
		job_id = job_id,
	}

	vim.notify("[gemini] Floating Diff Opened. <leader>aa: Accept, <leader>ad/q: Deny", vim.log.levels.INFO)

	-- Keymaps
	local function set_maps(buf)
		local m_opts = { buffer = buf, noremap = true, silent = true }
		vim.keymap.set("n", "<leader>aa", "<cmd>GeminiDiffAccept<cr>", m_opts)
		vim.keymap.set("n", "<leader>ad", "<cmd>GeminiDiffDeny<cr>", m_opts)
		vim.keymap.set("n", "q", "<cmd>GeminiDiffDeny<cr>", m_opts)
	end

	set_maps(bufnr)
	set_maps(scratch_buf)

	return ""
end

function M.diff_accept()
	local bufnr = vim.api.nvim_get_current_buf()
	for file_path, session in pairs(diff_sessions) do
		if session.bufnr == bufnr or session.scratch_buf == bufnr then
			M.accept_diff(file_path)
			return
		end
	end
	vim.notify("[gemini] No active diff session for this buffer.", vim.log.levels.WARN)
end

function M.diff_deny()
	local bufnr = vim.api.nvim_get_current_buf()
	for file_path, session in pairs(diff_sessions) do
		if session.bufnr == bufnr or session.scratch_buf == bufnr then
			M.reject_diff(file_path)
			return
		end
	end
	vim.notify("[gemini] No active diff session for this buffer.", vim.log.levels.WARN)
end

function M.accept_diff(file_path)
	if not file_path then
		return M.diff_accept()
	end
	local session = diff_sessions[file_path]
	if not session then
		return
	end

	local new_lines = vim.split(session.new_content, "\n")
	vim.api.nvim_buf_set_lines(session.bufnr, 0, -1, false, new_lines)

	-- Mark as unmodified so external tools (gemini edit)
	-- can write to disk without triggering a W12 conflict warning.
	vim.api.nvim_set_option_value("modified", false, { buf = session.bufnr })

	if session.job_id then
		vim.rpcnotify(session.job_id, "diff_accepted", {
			filePath = file_path,
			content = session.new_content,
		})
	end

	M.cleanup_session(file_path)
	vim.notify("[gemini] Diff accepted.", vim.log.levels.INFO)
end

function M.reject_diff(file_path)
	if not file_path then
		return M.diff_deny()
	end
	local session = diff_sessions[file_path]
	if not session then
		return
	end

	if session.job_id then
		vim.rpcnotify(session.job_id, "diff_rejected", {
			filePath = file_path,
		})
	end

	M.cleanup_session(file_path)
	vim.notify("[gemini] Diff denied.", vim.log.levels.INFO)
end

function M.cleanup_session(file_path)
	local session = diff_sessions[file_path]
	if not session then
		return
	end

	-- Close floating windows
	if session.win_left and vim.api.nvim_win_is_valid(session.win_left) then
		vim.api.nvim_win_close(session.win_left, true)
	end
	if session.win_right and vim.api.nvim_win_is_valid(session.win_right) then
		vim.api.nvim_win_close(session.win_right, true)
	end

	-- Wipe scratch buffer
	if session.scratch_buf and vim.api.nvim_buf_is_valid(session.scratch_buf) then
		vim.api.nvim_buf_delete(session.scratch_buf, { force = true })
	end

	-- Cleanup keymaps on original buffer
	if vim.api.nvim_buf_is_valid(session.bufnr) then
		pcall(vim.keymap.del, "n", "<leader>aa", { buffer = session.bufnr })
		pcall(vim.keymap.del, "n", "<leader>ad", { buffer = session.bufnr })
		pcall(vim.keymap.del, "n", "q", { buffer = session.bufnr })
	end

	diff_sessions[file_path] = nil
end

function M.close_diff(file_path)
	file_path = vim.fn.fnamemodify(file_path, ":p")
	M.cleanup_session(file_path)
	return { result = "closed" }
end

function M.get_context(preferred_bufnr)
	local context = {
		workspaceState = {
			openFiles = {},
			isTrusted = true,
		},
	}

	local current_buf = vim.api.nvim_get_current_buf()
	local buffers = vim.api.nvim_list_bufs()

	-- Determine effective active buffer
	local current_buftype = vim.api.nvim_get_option_value("buftype", { buf = current_buf })
	local effective_active_buf = current_buf
	if current_buftype ~= "" and preferred_bufnr and vim.api.nvim_buf_is_valid(preferred_bufnr) then
		effective_active_buf = preferred_bufnr
	end

	for _, bufnr in ipairs(buffers) do
		if vim.api.nvim_buf_is_loaded(bufnr) then
			local name = vim.api.nvim_buf_get_name(bufnr)
			local buftype = vim.api.nvim_get_option_value("buftype", { buf = bufnr })

			if name ~= "" and buftype == "" then
				local file_info = {
					path = name,
					timestamp = os.time(),
					isActive = (bufnr == effective_active_buf),
				}

				if file_info.isActive then
					-- Attempt to find the window for the active buffer
					local winid = vim.fn.bufwinid(bufnr)
					if winid ~= -1 then
						local cursor = vim.api.nvim_win_get_cursor(winid)
						file_info.cursor = {
							line = cursor[1],
							character = cursor[2] + 1,
						}
					end

					-- Capture selected text
					-- If currently in the active buffer, use standard methods.
					local mode = vim.fn.mode()
					if mode == "v" or mode == "V" or mode == "\22" then
						local start_pos = vim.fn.getpos("v")
						local end_pos = vim.fn.getpos(".")
						local ok, region = pcall(vim.fn.getregion, start_pos, end_pos, { type = mode })
						if ok and region then
							file_info.selectedText = table.concat(region, "\n")
						end
					end
				end

				table.insert(context.workspaceState.openFiles, file_info)
			end
		end
	end

	return context
end

-- --- LSP & Treesitter Tools ---

local function uri_to_relative_path(uri)
	local fname = vim.uri_to_fname(uri)
	return vim.fn.fnamemodify(fname, ":.")
end

function M.get_diagnostics(file_path)
	local diagnostics
	if file_path and file_path ~= "" then
		local bufnr = M.ensure_buffer(file_path)
		diagnostics = vim.diagnostic.get(bufnr)
	else
		-- Get all diagnostics
		diagnostics = vim.diagnostic.get()
	end

	if #diagnostics == 0 then
		return "Status: No diagnostics found."
	end

	-- Group by file
	local grouped = {}
	local error_count = 0
	local warn_count = 0

	for _, d in ipairs(diagnostics) do
		local buf = d.bufnr
		local path = vim.api.nvim_buf_get_name(buf)
		path = vim.fn.fnamemodify(path, ":.")
		if not grouped[path] then
			grouped[path] = {}
		end
		table.insert(grouped[path], d)

		if d.severity == vim.diagnostic.severity.ERROR then
			error_count = error_count + 1
		elseif d.severity == vim.diagnostic.severity.WARN then
			warn_count = warn_count + 1
		end
	end

	local lines = {
		string.format("Status: %d Errors, %d Warnings", error_count, warn_count),
	}

	for path, diags in pairs(grouped) do
		table.sort(diags, function(a, b)
			return a.lnum < b.lnum
		end)
		for _, d in ipairs(diags) do
			local severity = ({ "Error", "Warn", "Info", "Hint" })[d.severity] or "Unknown"
			local prefix = string.format("[%s]", severity:upper())
			table.insert(lines, "")
			-- Format: [ERROR] path/to/file.go:22
			table.insert(lines, string.format("%-7s %s:%d", prefix, path, d.lnum + 1))
			table.insert(lines, d.message)
		end
	end

	return table.concat(lines, "\n")
end

local function lsp_request(bufnr, method, params, timeout)
	timeout = timeout or 2000
	bufnr = vim._resolve_bufnr(bufnr)

	local method_cap_map = {
		["textDocument/definition"] = "definitionProvider",
		["textDocument/references"] = "referencesProvider",
		["textDocument/hover"] = "hoverProvider",
		["workspace/symbol"] = "workspaceSymbolProvider",
	}
	local required_cap = method_cap_map[method]

	-- Get relevant clients
	local get_clients = vim.lsp.get_clients or vim.lsp.get_active_clients
	local clients
	if method == "workspace/symbol" then
		clients = get_clients() -- Global search across all clients
	else
		clients = get_clients({ bufnr = bufnr })
	end

	local valid_clients = {}
	for _, client in ipairs(clients) do
		if not required_cap or client.server_capabilities[required_cap] then
			table.insert(valid_clients, client)
		end
	end

	if #valid_clients == 0 then
		return {}, nil
	end

	local results = {}
	local err = nil

	for _, client in ipairs(valid_clients) do
		local response = client.request_sync(method, params, timeout, bufnr)
		if response then
			if response.result then
				results[client.id] = { result = response.result }
			elseif response.err and not err then
				err = response.err
			end
		end
	end

	return results, err
end

local function get_smart_position(bufnr, line, col)
	-- Inputs are 1-based line, 0-based col
	local row = line - 1
	local col_idx = col

	local function try_get_smart()
		local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
		if not ok or not parser then
			return nil
		end

		local tree = parser:parse()[1]
		local root = tree:root()
		
		-- Strategy 1: Exact position
		local node = root:named_descendant_for_range(row, col_idx, row, col_idx)
		if node then
			if type(node) == "table" then node = node[1] end
			local node_type = node:type()
			if node_type and node_type:match("identifier") then
				local r, c, _ = node:start()
				return { r, c }
			end
			-- Handle field/method names inside declarations
			if node.child_by_field_name then
				local name_node = node:child_by_field_name("name")
				if name_node then
					if type(name_node) == "table" then name_node = name_node[1] end
					local r, c, _ = name_node:start()
					return { r, c }
				end
			end
		end

		-- Strategy 2: Scan line for first identifier
		-- This helps when agent provides character: 0
		local line_text = vim.api.nvim_buf_get_lines(bufnr, row, row + 1, false)[1] or ""
		-- Simple heuristic: find first alphanumeric word
		local s, e = line_text:find("[%a_][%w_]*")
		if s then
			-- Verify with TS if possible
			local candidate = root:named_descendant_for_range(row, s - 1, row, e - 1)
			if candidate then
				if type(candidate) == "table" then candidate = candidate[1] end
				local r, c, _ = candidate:start()
				return { r, c }
			end
			-- Fallback to regex match position
			return { row, s - 1 }
		end

		return nil
	end

	local ok, res = pcall(try_get_smart)
	if ok and res then
		return res[1], res[2]
	end

	return row, col_idx
end

function M.get_definition(file_path, line, col)
	local bufnr = M.ensure_buffer(file_path)
	local r, c = get_smart_position(bufnr, line, col)
	local params = {
		textDocument = { uri = vim.uri_from_bufnr(bufnr) },
		position = { line = r, character = c },
	}

	local result, err = lsp_request(bufnr, "textDocument/definition", params)
	if err then
		return "Error: " .. tostring(err)
	end

	local locations = {}
	for _, res in pairs(result or {}) do
		if res.result then
			local defs = res.result
			if not vim.islist(defs) then
				defs = { defs }
			end
			for _, def in ipairs(defs) do
				local uri = def.uri or def.targetUri
				local range = def.range or def.targetSelectionRange
				local path = uri_to_relative_path(uri)
				table.insert(
					locations,
					string.format("%s:%d:%d", path, range.start.line + 1, range.start.character + 1)
				)
			end
		end
	end

	if #locations == 0 then
		return "No definitions found."
	end
	return table.concat(locations, "\n")
end

function M.get_references(file_path, line, col)
	local bufnr = M.ensure_buffer(file_path)
	local r, c = get_smart_position(bufnr, line, col)
	local params = {
		textDocument = { uri = vim.uri_from_bufnr(bufnr) },
		position = { line = r, character = c },
		context = { includeDeclaration = true },
	}

	local result, err = lsp_request(bufnr, "textDocument/references", params)
	if err then
		return "Error: " .. tostring(err)
	end

	local refs = {}
	for _, res in pairs(result or {}) do
		if res.result then
			for _, loc in ipairs(res.result) do
				table.insert(refs, loc)
			end
		end
	end

	if #refs == 0 then
		return "No references found."
	end

	-- Sort by URI then line
	table.sort(refs, function(a, b)
		if a.uri == b.uri then
			return a.range.start.line < b.range.start.line
		end
		return a.uri < b.uri
	end)

	local output = {}
	local context_lines = 1 -- Lines before and after

	for _, loc in ipairs(refs) do
		local uri = loc.uri
		local range = loc.range
		local fname = vim.uri_to_fname(uri)
		local ref_buf = M.ensure_buffer(fname)
		local line_num = range.start.line -- 0-based

		local start_l = math.max(0, line_num - context_lines)
		local end_l = line_num + context_lines + 1
		local lines = vim.api.nvim_buf_get_lines(ref_buf, start_l, end_l, false)

		local path = uri_to_relative_path(uri)
		table.insert(output, string.format("Location: %s:%d:%d", path, line_num + 1, range.start.character + 1))

		for i, text in ipairs(lines) do
			local curr_l = start_l + i -- 1-based line number for display
			local marker = (curr_l == line_num + 1) and ">" or " "
			table.insert(output, string.format("%s %4d | %s", marker, curr_l, text))
		end
		table.insert(output, "")
	end

	return table.concat(output, "\n")
end

function M.get_hover(file_path, line, col)
	local bufnr = M.ensure_buffer(file_path)
	local r, c = get_smart_position(bufnr, line, col)
	local params = {
		textDocument = { uri = vim.uri_from_bufnr(bufnr) },
		position = { line = r, character = c },
	}

	local result, err = lsp_request(bufnr, "textDocument/hover", params)
	if err then
		return "Error: " .. tostring(err)
	end

	local contents = {}
	for _, res in pairs(result or {}) do
		if res.result and res.result.contents then
			local content = res.result.contents
			if type(content) == "table" and content.value then
				table.insert(contents, content.value)
			elseif type(content) == "string" then
				table.insert(contents, content)
			elseif type(content) == "table" then
				-- MarkupContent or array of MarkedString
				if content.kind and content.value then
					table.insert(contents, content.value)
				else
					for _, c in ipairs(content) do
						if type(c) == "string" then
							table.insert(contents, c)
						elseif c.value then
							table.insert(contents, c.value)
						end
					end
				end
			end
		end
	end

	if #contents == 0 then
		return "No hover information found."
	end
	return table.concat(contents, "\n\n")
end

local function get_node_text(node, bufnr)
	if not node then
		return ""
	end

	-- Handle table (list of nodes) returned by iter_matches
	if type(node) == "table" then
		node = node[1]
	end

	-- Use pcall to try standard method first, fallback to manual range
	local ok, text = pcall(vim.treesitter.get_node_text, node, bufnr)
	if ok then
		return text
	end

	-- Fallback for environments where node:range() is broken
	-- node:start() -> row, col, bytes
	local start_row, start_col, _ = node:start()
	local end_row, end_col, _ = node:end_()

	local lines = vim.api.nvim_buf_get_text(bufnr, start_row, start_col, end_row, end_col, {})
	return table.concat(lines, "\n")
end

function M.get_treesitter_node(file_path, line, col)
	local bufnr = M.ensure_buffer(file_path)
	local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
	if not ok or not parser then
		return "Error: No treesitter parser found."
	end

	local tree = parser:parse()[1]
	local root = tree:root()
	local node = root:named_descendant_for_range(line - 1, col, line - 1, col)

	if not node then
		return "Error: No node found at position."
	end

	local type = node:type()
	local r1, c1, _ = node:start()
	local r2, c2, _ = node:end_()
	local text = get_node_text(node, bufnr)
	local parent = node:parent()
	local parent_type = parent and parent:type() or "nil"

	return string.format(
		"Type: %s\nRange: %d:%d - %d:%d\nParent: %s\nText:\n%s",
		type,
		r1 + 1,
		c1 + 1,
		r2 + 1,
		c2 + 1,
		parent_type,
		text
	)
end

function M.run_treesitter_query(file_path, query_string)
	local bufnr = M.ensure_buffer(file_path)
	local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
	if not ok or not parser then
		return "Error: No treesitter parser found."
	end

	local lang = parser:lang()
	local query_ok, query = pcall(vim.treesitter.query.parse, lang, query_string)
	if not query_ok then
		return "Error: Invalid query: " .. tostring(query)
	end

	local tree = parser:parse()[1]
	local root = tree:root()
	local matches = {}

	for id, node, _ in query:iter_captures(root, bufnr, 0, -1) do
		local name = query.captures[id]
		if type(node) == "table" then
			node = node[1]
		end
		local r1, c1, _ = node:start()
		local r2, c2, _ = node:end_()
		local text = get_node_text(node, bufnr)
		table.insert(
			matches,
			string.format("Capture: %s\nRange: %d:%d - %d:%d\nText:\n%s", name, r1 + 1, c1 + 1, r2 + 1, c2 + 1, text)
		)
	end

	if #matches == 0 then
		return "No matches found."
	end
	return table.concat(matches, "\n---\n")
end

local function get_symbol_kind_name(kind)
	local kinds = {
		[1] = "File",
		[2] = "Module",
		[3] = "Namespace",
		[4] = "Package",
		[5] = "Class",
		[6] = "Method",
		[7] = "Property",
		[8] = "Field",
		[9] = "Constructor",
		[10] = "Enum",
		[11] = "Interface",
		[12] = "Function",
		[13] = "Variable",
		[14] = "Constant",
		[15] = "String",
		[16] = "Number",
		[17] = "Boolean",
		[18] = "Array",
		[19] = "Object",
		[20] = "Key",
		[21] = "Null",
		[22] = "EnumMember",
		[23] = "Struct",
		[24] = "Event",
		[25] = "Operator",
		[26] = "TypeParameter",
	}
	return kinds[kind] or "Unknown"
end

function M.search_workspace_symbol(query)
	local params = { query = query }
	local result, err = lsp_request(0, "workspace/symbol", params, 5000)
	if err then
		return "Error: " .. tostring(err)
	end

	local matches = {}
	local count = 0
	for _, res in pairs(result or {}) do
		if res.result then
			for _, sym in ipairs(res.result) do
				count = count + 1
				if count > 30 then
					break
				end
				local path = uri_to_relative_path(sym.location.uri)
				local kind = get_symbol_kind_name(sym.kind)
				table.insert(
					matches,
					string.format("[%s] %-20s (%s:%d)", kind, sym.name, path, sym.location.range.start.line + 1)
				)
			end
		end
		if count > 30 then
			break
		end
	end

	if #matches == 0 then
		return "No symbols found for query: " .. query
	end

	local header = string.format('Found %d matches for "%s":', #matches, query)
	return header .. "\n" .. table.concat(matches, "\n")
end

function M.get_workspace_structure(root_dir, max_depth)
	root_dir = root_dir or vim.fn.getcwd()
	max_depth = max_depth or 2

	local cmd = "git ls-files"
	if vim.fn.isdirectory(root_dir .. "/.git") == 0 then
		cmd = "find . -maxdepth " .. (max_depth + 1) .. " -not -path '*/.*'"
	end

	local handle = io.popen("cd " .. vim.fn.shellescape(root_dir) .. " && " .. cmd)
	if not handle then
		return "Error: Failed to list files."
	end
	local output = handle:read("*a")
	handle:close()

	local files = vim.split(output, "\n")
	local tree = {}

	for _, file in ipairs(files) do
		if file ~= "" then
			local parts = vim.split(file, "/")
			local current = tree
			for i, part in ipairs(parts) do
				if i > max_depth + 1 then
					break
				end
				if i == #parts then
					current[part] = current[part] or true
				else
					current[part] = current[part] or {}
					if type(current[part]) ~= "table" then
						current[part] = { ["_file"] = true }
					end
					current = current[part]
				end
			end
		end
	end

	local lines = { "/" .. vim.fn.fnamemodify(root_dir, ":t") }
	local function render_tree(node, depth, prefix)
		local keys = vim.tbl_keys(node)
		table.sort(keys)

		for i, key in ipairs(keys) do
			if key ~= "_file" then
				local is_last = (i == #keys)
				local char = is_last and "└── " or "├── "
				local next_prefix = prefix .. (is_last and "    " or "│   ")

				if type(node[key]) == "table" then
					table.insert(lines, prefix .. char .. key .. "/")
					if depth < max_depth then
						render_tree(node[key], depth + 1, next_prefix)
					end
				else
					table.insert(lines, prefix .. char .. key)
				end
			end
		end
	end

	render_tree(tree, 0, "")
	return table.concat(lines, "\n")
end

local function get_outline_query(lang)
	local queries = {
		go = [[ 
      (function_declaration name: (identifier) @name) @func
      (method_declaration name: (field_identifier) @name) @method
      (type_spec name: (type_identifier) @name) @type
      (var_spec name: (identifier) @name) @var
      (short_var_declaration left: (expression_list (identifier) @name)) @var
      (field_declaration name: (field_identifier) @name) @field
    ]],
		lua = [[ 
      (function_declaration name: [
        (identifier)
        (dot_index_expression)
        (method_index_expression)
      ] @name) @func
      (assignment_statement
        (variable_list (identifier) @name)
        (expression_list value: (function_definition))
      ) @func_assign
      (variable_declaration (assignment_statement (variable_list (identifier) @name))) @var
      (assignment_statement (variable_list (identifier) @name)) @var
      (field name: (identifier) @name value: (function_definition)) @method
    ]],
		python = [[ 
      (function_definition name: (identifier) @name) @func
      (class_definition name: (identifier) @name) @class
      (expression_statement (assignment left: (identifier) @name)) @var
    ]],
		rust = [[ 
      (function_item name: (identifier) @name) @func
      (struct_item name: (type_identifier) @name) @struct
      (enum_item name: (type_identifier) @name) @enum
      (trait_item name: (type_identifier) @name) @trait
      (impl_item type: (type_identifier) @name) @impl
      (const_item name: (identifier) @name) @const
      (static_item name: (identifier) @name) @static
      (macro_definition name: (identifier) @name) @macro
    ]],
		javascript = [[ 
      (function_declaration name: (identifier) @name) @func
      (class_declaration name: (identifier) @name) @class
      (method_definition name: (property_identifier) @name) @method
      (variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression)]) @arrow_func
      (lexical_declaration (variable_declarator name: (identifier) @name)) @var
      (variable_declaration (variable_declarator name: (identifier) @name)) @var
    ]],
		typescript = [[ 
      (function_declaration name: (identifier) @name) @func
      (class_declaration name: (type_identifier) @name) @class
      (interface_declaration name: (type_identifier) @name) @interface
      (method_definition name: (property_identifier) @name) @method
      (variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression)]) @arrow_func
      (type_alias_declaration name: (type_identifier) @name) @type
      (lexical_declaration (variable_declarator name: (identifier) @name)) @var
      (variable_declaration (variable_declarator name: (identifier) @name)) @var
      (enum_declaration name: (identifier) @name) @enum
    ]],
		php = [[ 
      (function_definition name: (name) @name) @func
      (method_declaration name: (name) @name) @method
      (class_declaration name: (name) @name) @class
      (interface_declaration name: (name) @name) @interface
      (trait_declaration name: (name) @name) @trait
      (const_declaration (const_element name: (name) @name)) @const
      (property_declaration (property_element variable: (variable_name) @name)) @field
    ]],
	}
	return queries[lang]
end

function M.get_file_outline(file_path)
	local bufnr = M.ensure_buffer(file_path)
	local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
	if not ok or not parser then
		return "Error: No treesitter parser found for file."
	end

	local lang = parser:lang()
	local query_string = get_outline_query(lang)
	if not query_string then
		return string.format("Error: Outline not supported for language '%s'.", lang)
	end

	local query = vim.treesitter.query.parse(lang, query_string)
	local tree = parser:parse()[1]
	local root = tree:root()

	local lines = {
		string.format("File: %s", vim.fn.fnamemodify(file_path, ":.")),
		string.rep("-", 40),
	}

	for _, match, _ in query:iter_matches(root, bufnr, 0, -1) do
		local type_node = nil
		local name_node = nil
		local extra_info = ""
		local type_display = "Unknown"

		for id, node in pairs(match) do
			local capture_name = query.captures[id]
			if capture_name == "name" then
				name_node = node
			elseif capture_name == "receiver" then
				extra_info = get_node_text(node, bufnr)
			elseif capture_name == "type_info" then
				extra_info = get_node_text(node, bufnr)
			else
				local map = {
					func = "Func",
					method = "Method",
					struct = "Struct",
					interface = "Interface",
					class = "Class",
					const = "Const",
					field = "Field",
					["var"] = "Var",
					arrow_func = "Func",
					type = "Type",
					enum = "Enum",
					trait = "Trait",
					impl = "Impl",
					func_assign = "Func",
				}
				if map[capture_name] then
					type_display = map[capture_name]
					type_node = node
				end
			end
		end

		if name_node and type_node then
			if type(type_node) == "table" then
				type_node = type_node[1]
			end
			if type(name_node) == "table" then
				name_node = name_node[1]
			end
			local r1, _, _ = type_node:start()
			local line_num = string.format("L%-4d", r1 + 1)
			local symbol_type = string.format("[%s]", type_display)
			local name = get_node_text(name_node, bufnr)

			local full_display = name
			if type_display == "Method" and extra_info ~= "" then
				-- Go method style: (r *Receiver) Method
				extra_info = extra_info:gsub("%s+", " ")
				full_display = string.format("%s %s", extra_info, name)
			elseif type_display == "Field" and extra_info ~= "" then
				-- Field style: - name Type
				full_display = string.format("- %s %s", name, extra_info)
			end

			table.insert(lines, string.format("%s %-10s %s", line_num, symbol_type, full_display))
		end
	end

	if #lines == 2 then
		return "No symbols found in outline."
	end

	return table.concat(lines, "\n")
end

local function get_node_with_comments(node, bufnr)
	if not node then
		return nil
	end
	if type(node) == "table" then
		node = node[1]
	end

	local start_row, start_col, _ = node:start()
	local end_row, end_col, _ = node:end_()

	-- Look-behind for comments
	local current = node
	while true do
		local prev = current:prev_sibling()
		if not prev then
			break
		end

		local p_type = prev:type()
		-- Common comment types across grammars: comment, line_comment, block_comment
		if p_type:find("comment") then
			current = prev
			start_row, start_col, _ = current:start()
		else
			-- Stop at anything that isn't a comment
			break
		end
	end

	local lines = vim.api.nvim_buf_get_text(bufnr, start_row, start_col, end_row, end_col, {})
	return {
		text = table.concat(lines, "\n"),
		start_line = start_row + 1,
		end_line = end_row + 1,
	}
end

function M.read_symbol(file_path, symbol_name)
	local bufnr = M.ensure_buffer(file_path)
	local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
	if not ok or not parser then
		return "Error: No treesitter parser found for file."
	end

	local lang = parser:lang()
	local query_string = get_outline_query(lang)
	if not query_string then
		return string.format("Error: Symbol reading not supported for language '%s'.", lang)
	end

	local query = vim.treesitter.query.parse(lang, query_string)
	local tree = parser:parse()[1]
	local root = tree:root()

	local results = {}

	for _, match, _ in query:iter_matches(root, bufnr, 0, -1) do
		local name_node = nil
		local major_node = nil

		for id, node in pairs(match) do
			local capture_name = query.captures[id]
			if capture_name == "name" then
				name_node = node
			else
				-- Other captures in get_outline_query are the major nodes (func, struct, etc.)
				major_node = node
			end
		end

		if name_node and major_node then
			local actual_name = get_node_text(name_node, bufnr)
			if actual_name == symbol_name then
				local expanded = get_node_with_comments(major_node, bufnr)
				if expanded then
					table.insert(results, expanded)
				end
			end
		end
	end

	if #results == 0 then
		return string.format("Symbol '%s' not found in %s", symbol_name, file_path)
	end

	local output = {}
	for _, res in ipairs(results) do
		table.insert(
			output,
			string.format("File: %s (Lines %d-%d)", vim.fn.fnamemodify(file_path, ":."), res.start_line, res.end_line)
		)
		table.insert(output, string.format("Symbol: %s", symbol_name))
		table.insert(output, "\n```" .. lang .. "\n" .. res.text .. "\n```")
		table.insert(output, "\n" .. string.rep("-", 40) .. "\n")
	end

	return table.concat(output, "\n")
end

function M.resolve_definition(file_path, line, col)
	local bufnr = M.ensure_buffer(file_path)
	local r, c = get_smart_position(bufnr, line, col)
	local params = {
		textDocument = { uri = vim.uri_from_bufnr(bufnr) },
		position = { line = r, character = c },
	}

	-- 1. LSP Definition
	local result, err = lsp_request(bufnr, "textDocument/definition", params)
	if err then
		return "Error: " .. tostring(err)
	end

	local location = nil
	for _, res in pairs(result or {}) do
		if res.result then
			local defs = res.result
			if vim.islist(defs) then
				location = defs[1]
			else
				location = defs
			end
			if location then
				break
			end
		end
	end

	if not location then
		return "No definition found at cursor."
	end

	local target_uri = location.uri or location.targetUri
	local target_range = location.range or location.targetSelectionRange
	local target_path = vim.uri_to_fname(target_uri)
	local target_bufnr = M.ensure_buffer(target_path)

	-- 2. Tree-sitter Expansion
	local ok, parser = pcall(vim.treesitter.get_parser, target_bufnr)
	if not ok or not parser then
		-- Fallback to just reading lines if TS is not available
		local start_l = target_range.start.line
		local end_l = target_range["end"].line
		local lines = vim.api.nvim_buf_get_lines(target_bufnr, start_l, end_l + 1, false)
		return string.format(
			"File: %s (Lines %d-%d)\n\n```\n%s\n```",
			vim.fn.fnamemodify(target_path, ":."),
			start_l + 1,
			end_l + 1,
			table.concat(lines, "\n")
		)
	end

	local tree = parser:parse()[1]
	local root = tree:root()
	local node = root:named_descendant_for_range(
		target_range.start.line,
		target_range.start.character,
		target_range.start.line,
		target_range.start.character
	)

	if not node then
		return "Error: Target node not found in Tree-sitter tree."
	end

	-- Traverse up to find a "major" node (Function, Struct, Class, etc.)
	local major_types = {
		"function_declaration",
		"method_declaration",
		"type_declaration",
		"struct_item",
		"enum_item",
		"function_definition",
		"class_definition",
		"class_declaration",
		"method_definition",
		"function_item",
		"trait_item",
		"impl_item",
	}

	local current = node
	local found_major = nil
	while current do
		local n_type = current:type()
		for _, m_type in ipairs(major_types) do
			if n_type == m_type then
				found_major = current
				break
			end
		end
		if found_major then
			break
		end
		current = current:parent()
	end

	-- If no major node found, use the direct node
	local target_node = found_major or node
	local expanded = get_node_with_comments(target_node, target_bufnr)

	if not expanded then
		return "Error: Could not extract code block."
	end

	return string.format(
		"File: %s (Lines %d-%d)\n\n```%s\n%s\n```",
		vim.fn.fnamemodify(target_path, ":."),
		expanded.start_line,
		expanded.end_line,
		parser:lang(),
		expanded.text
	)
end

return M
