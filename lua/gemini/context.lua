local M = {}

local MAX_FILES = 10
local MAX_SELECTED_TEXT_LENGTH = 16384 -- 16 KiB limit

-- Array of { path = string, timestamp = number }
local open_files = {}

local function is_file_buf(bufnr)
	if not vim.api.nvim_buf_is_valid(bufnr) then
		return false
	end
	local buftype = vim.api.nvim_get_option_value("buftype", { buf = bufnr })
	local name = vim.api.nvim_buf_get_name(bufnr)
	return buftype == "" and name ~= ""
end

local function get_ms_timestamp()
	-- vim.loop.hrtime() is in nanoseconds
	return math.floor(vim.loop.hrtime() / 1000000)
end

function M.add_or_move_to_front(bufnr)
	if not is_file_buf(bufnr) then
		return
	end

	local path = vim.api.nvim_buf_get_name(bufnr)
	local timestamp = get_ms_timestamp()

	-- Remove if already in list
	for i, file in ipairs(open_files) do
		if file.path == path then
			table.remove(open_files, i)
			break
		end
	end

	-- Add to front
	table.insert(open_files, 1, {
		path = path,
		timestamp = timestamp,
		bufnr = bufnr,
	})

	-- Enforce limit
	if #open_files > MAX_FILES then
		table.remove(open_files)
	end
end

function M.remove_file(path)
	for i, file in ipairs(open_files) do
		if file.path == path then
			table.remove(open_files, i)
			break
		end
	end
end

function M.rename_file(old_path, new_path)
	for _, file in ipairs(open_files) do
		if file.path == old_path then
			file.path = new_path
			break
		end
	end
end

function M.get_context(preferred_bufnr)
	local current_buf = vim.api.nvim_get_current_buf()
	local effective_active_buf = current_buf

	-- If we are in a special buffer (like a floating window or quickfix), 
	-- try to use the preferred buffer provided by the caller (last valid file buffer).
	if not is_file_buf(current_buf) and preferred_bufnr and is_file_buf(preferred_bufnr) then
		effective_active_buf = preferred_bufnr
	end

	-- Always ensure the effective active buffer is at the front of our LRU
	if is_file_buf(effective_active_buf) then
		M.add_or_move_to_front(effective_active_buf)
	end

	local context = {
		workspaceState = {
			openFiles = {},
			isTrusted = true,
		},
	}

	for _, file in ipairs(open_files) do
		-- Only include if buffer is still loaded and valid
		if vim.api.nvim_buf_is_valid(file.bufnr) and vim.api.nvim_buf_is_loaded(file.bufnr) then
			local file_info = {
				path = file.path,
				timestamp = file.timestamp,
				isActive = (file.bufnr == effective_active_buf),
			}

			if file_info.isActive then
				-- Cursor position
				local winid = vim.fn.bufwinid(file.bufnr)
				if winid ~= -1 then
					local cursor = vim.api.nvim_win_get_cursor(winid)
					file_info.cursor = {
						line = cursor[1],
						character = cursor[2] + 1,
					}
				end

				-- Selected text (only if active)
				local mode = vim.fn.mode()
				if mode == "v" or mode == "V" or mode == "\22" then
					local start_pos = vim.fn.getpos("v")
					local end_pos = vim.fn.getpos(".")
					local ok, region = pcall(vim.fn.getregion, start_pos, end_pos, { type = mode })
					if ok and region then
						local selected = table.concat(region, "\n")
						if #selected > MAX_SELECTED_TEXT_LENGTH then
							selected = selected:sub(1, MAX_SELECTED_TEXT_LENGTH)
						end
						file_info.selectedText = selected
					end
				end
			end

			table.insert(context.workspaceState.openFiles, file_info)
		end
	end

	return context
end

return M
