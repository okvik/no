local co = require "coroutine"
local unpack, pack = string.unpack, string.pack
local min, abs = math.min, math.abs

local dump = (function()
	local ok, mod = pcall(require, "dump")
	return ok and mod or print
end)()

local no = {}

no.Tversion, no.Rversion = 100, 101
no.Tauth, no.Rauth = 102, 103
no.Tattach, no.Rattach = 104, 105
no.Terror, no.Rerror = 106, 107
no.Tflush, no.Rflush = 108, 109
no.Twalk, no.Rwalk = 110, 111
no.Topen, no.Ropen = 112, 113
no.Tcreate, no.Rcreate = 114, 115
no.Tread, no.Rread = 116, 117
no.Twrite, no.Rwrite = 118, 119
no.Tclunk, no.Rclunk = 120, 121
no.Tremove, no.Rremove = 122, 123
no.Tstat, no.Rstat = 124, 125
no.Twstat, no.Rwstat = 126, 127

no.NOTAG, no.NOFID = 0xFFFF, 0xFFFFFFFF

-- Bits of Qid.type
no.QTDIR = 0x80
no.QTAPPEND = 0x40
no.QTEXCL = 0x20
no.QTMOUNT = 0x10
no.QTAUTH = 0x08
no.QTTMP = 0x04
no.QTFILE = 0x00

-- Bits of Dir.mode
no.DMDIR = 0x80000000
no.DMAPPEND = 0x40000000
no.DMEXCL = 0x20000000
no.DMMOUNT = 0x10000000
no.DMAUTH = 0x08000000
no.DMTMP = 0x04000000
no.DMREAD = 0x4
no.DMWRITE = 0x2
no.DMEXEC = 0x1

-- Open mode
no.OREAD = 0x0
no.OWRITE = 0x1
no.ORDWR = 0x2
no.OEXEC = 0x3
no.OTRUNC = 0x10
no.OCEXEC = 0x20
no.ORCLOSE = 0x40
no.EXCL = 0x1000

no.Ebotch = "9P protocol botch"

local tohuman = {
	[no.Tversion] = "Tversion", [no.Rversion] = "Rversion",
	[no.Tauth] = "Tauth", [no.Rauth] = "Rauth",
	[no.Terror] = "Terror", [no.Rerror] = "Rerror",
	[no.Tflush] = "Tflush", [no.Rflush] = "Rflush",
	[no.Tattach] = "Tattach", [no.Rattach] = "Rattach",
	[no.Twalk] = "Twalk", [no.Rwalk] = "Rwalk",
	[no.Topen] = "Topen", [no.Ropen] = "Ropen",
	[no.Tcreate] = "Tcreate", [no.Rcreate] = "Rcreate",
	[no.Tread] = "Tread", [no.Rread] = "Rread",
	[no.Twrite] = "Twrite", [no.Rwrite] = "Rwrite",
	[no.Tclunk] = "Tclunk", [no.Rclunk] = "Rclunk",
	[no.Tremove] = "Tremove", [no.Rremove] = "Rremove",
	[no.Tstat] = "Tstat", [no.Rstat] = "Rstat",
	[no.Twstat] = "Twstat", [no.Rwstat] = "Rwstat",
}
local fmt = string.format
local qidfmt = function(qid)
	return fmt("(path=%d type=%d vers=%d)", qid.path, qid.type, qid.vers)
end
local tracefn = {
	[no.Tattach] = function(T)
		return fmt("afid=%d uname=%s aname=%s", T.afid, T.uname, T.aname)
	end;
	[no.Rattach] = function(R)
		return fmt("qid=%s", qidfmt(R.qid))
	end;
	[no.Twalk] = function(T)
		return fmt("nwname=%d wname=(%s)", T.nwname, table.concat(T.wname, " "))
	end;
	[no.Rwalk] = function(R)
		local buf = fmt("nwqid=%d ", #R.wqid)
		for i = 1, #R.wqid do
			buf = buf .. fmt("%s ", qidfmt(R.wqid[i]))
		end
		return buf
	end;
	[no.Rerror] = function(R)
		return R.ename
	end;
}
local function trace(TR)
	local buf = fmt("%s %s\n",
		tohuman[TR.type],
		tracefn[TR.type] and tracefn[TR.type](TR) or "")
	io.stderr:write(buf)
end

local decode = {
	[no.Tversion] = function(T, buf, p)
		T.msize, T.version, p = unpack("< I4 s2", buf, p)
		T.msize = abs(T.msize)
		return p
	end;
	[no.Tauth] = function(T, buf, p)
		T.afid, T.uname, T.aname, p = unpack("< I4 s2 s2", buf, p)
		return p
	end;
	[no.Tflush] = function(T, buf, p)
		T.oldtag, p = unpack("< I2", buf, p)
		return p
	end;
	[no.Tattach] = function(T, buf, p)
		T.fid, T.afid, T.uname, T.aname, p = unpack("< I4 I4 s2 s2", buf, p)
		return p
	end;
	[no.Twalk] = function(T, buf, p)
		T.fid, T.newfid, T.nwname, p = unpack("< I4 I4 I2", buf, p)
		T.wname = {}
		for _ = 1, T.nwname do
			local name
			name, p = unpack("< s2", buf, p)
			table.insert(T.wname, name)
		end
		return p
	end;
	[no.Topen] = function(T, buf, p)
		T.fid, T.mode, p = unpack("< I4 I1", buf, p)
		return p
	end;
	[no.Tcreate] = function(T, buf, p)
		T.fid, T.name, T.perm, T.mode, p = unpack("< I4 s2 I4 I1", buf, p)
		return p
	end;
	[no.Tread] = function(T, buf, p)
		T.fid, T.offset, T.count, p = unpack("< I4 I8 I4", buf, p)
		T.count = abs(T.count)
		return p
	end;
	[no.Twrite] = function(T, buf, p)
		T.fid, T.offset, T.count, p = unpack("< I4 I8 I4", buf, p)
		T.count = abs(T.count)
		T.data, p = unpack("c" .. T.count, buf, p)
		return p
	end;
	[no.Tclunk] = function(T, buf, p)
		T.fid, p = unpack("< I4", buf, p)
		return p
	end;
	[no.Tremove] = function(T, buf, p)
		T.fid, p = unpack("< I4", buf, p)
		return p
	end;
	[no.Tstat] = function(T, buf, p)
		T.fid, p = unpack("< I4", buf, p)
		return p
	end;
	[no.Twstat] = function(T, buf, p)
		T.fid, T.stat, p = unpack("< I4 s2", buf, p)
		return p
	end
}
function no.decode(read)
	local T = {}
	local buf = read(4)
	T.size = unpack("< I4", buf)
	buf = read(T.size - 4); assert(#buf == T.size - 4)
	local p
	T.type, T.tag, p = unpack("< I1 I2", buf)
	p = decode[T.type](T, buf, p)
	if p < #buf then
		error("error decoding message")
	end
	return T
end

local encodeqid = function(qid)
	return pack("< I1 I4 I8", qid.type, qid.vers, qid.path)
end
local encodestat = function(stat)
	local buf = pack("< I2 I4 c13 I4 I4 I4 I8 s2 s2 s2 s2",
		0, 0, encodeqid(stat.qid),
		stat.mode, stat.atime, stat.mtime, stat.length,
		stat.name, stat.uid, stat.gid, stat.muid
	)
	return pack("< I2", #buf) .. buf
end
local encode = {
	[no.Rversion] = function(R)
		return pack("< I4 s2", R.msize, R.version) end;
	[no.Rerror] = function(R)
		return pack("< s2", R.ename) end;
	[no.Rflush] = function(R)
		return pack("< I2", R.oldtag) end;
	[no.Rauth] = function(R)
		return encodeqid(R.qid) end;
	[no.Rattach] = function(R)
		return encodeqid(R.qid) end;
	[no.Rwalk] = function(R)
		local t = {}
		t[1] = pack("< I2", #R.wqid)
		for i = 1, #R.wqid do
			table.insert(t, encodeqid(R.wqid[i]))
		end
		return table.concat(t)
	end;
	[no.Ropen] = function(R)
		return pack("< c13 I4", encodeqid(R.qid), R.iounit) end;
	[no.Rcreate] = function(R)
		return pack("< c13 I4", encodeqid(R.qid), R.iounit) end;
	[no.Rread] = function(R)
		return pack("< I4", R.count or #R.data) .. R.data end;
	[no.Rwrite] = function(R)
		return pack("< I4", R.count) end;
	[no.Rclunk] = function() end;
	[no.Rremove] = function() end;
	[no.Rwstat] = function() end;
	[no.Rstat] = function(R)
		local buf = encodestat(R.stat, R.stat.qid)
		return pack("< I2", #buf) .. buf
	end;
}
function no.encode(R)
	if not encode[R.type] then
		return nil, "unknown request type"
	end
	local buf = encode[R.type](R) or ""
	return pack("< I4 I1 I2", 4+1+2 + #buf, R.type, R.tag) .. buf
end

local function respond(T, S, R)
	R = R or {}
	R.tag = T.tag
	if R.error then
		R.type = no.Rerror
		R.ename = R.error
	else
		R.type = T.type + 1
	end
	local buf, err = no.encode(R)
	if not buf then
		error(err)
	end
	S.writer(buf)
	S.tags[T.tag] = nil
end

local function listdir(T, S)
	local stats = S.list(T)
	if #stats == 0 then
		return ""
	end
	local data = {}
	local left = S.iounit
	for i = 1, #stats do
		local buf = encodestat(stats[i])
		left = left - #buf
		if left < 0 then
			co.yield(table.concat(data))
			data = {}
			left = S.iounit - #buf
		end
		table.insert(data, buf)
	end
	co.yield(table.concat(data))
	return "done"
end

local dispatch = {
	[no.Tversion] = function(T, S)
		S.msize = min(T.msize, S.msize)
		local R = {}
		R.msize = S.msize
		if T.version:match("^9P") then
			R.version = "9P2000"
		else
			R.version = "unknown"
		end
		T:respond(R)
	end;
	[no.Tflush] = function(T, S)
		local oldT = S.tags[T.oldtag]
		if not oldT or not S.flush then
			-- Already responded or no delayed responses
			T:respond()
		else
			-- User must ensure the delayed response is canceled
			S.flush(T, oldT)
		end
	end;
	[no.Tauth] = function(T)
		T:error("authentication not required")
	end;
	[no.Tattach] = function(T, S)
		if S.fids[T.fid] then
			T:error("duplicate fid")
			return
		end
		T.state = {}
		T.state.user = T.uname
		T.state.tree = T.aname
		T.respond = function(_, qid)
			respond(T, S, {qid = qid})
			T.state.qid = qid
			S.fids[T.fid] = T.state
		end
		S.attach(T)
	end;
	[no.Twalk] = function(T, S)
		if not S.fids[T.fid] then
			T:error("unknown fid"); return
		end
		if T.state.mode then
			T:error("cannot clone open fid"); return
		end
		if T.nwname > 0 and not (T.state.qid.type & no.QTDIR > 0) then
			T:error("walk in a non-directory"); return
		end
		T.move = T.fid == T.newfid
		T.clone = not T.move and T.nwname == 0
		if T.move then
			T.newstate = T.state
		else
			if S.fids[T.newfid] then
				T:error("duplicate fid"); return
			end
			T.newstate = {
				user = T.state.user,
				tree = T.state.tree,
				qid = T.state.qid,
			}
		end
		T.respond = function(_, wqid)
			wqid = wqid or {}
			local newstate = T.newstate
			if #wqid < T.nwname then
				if #wqid == 0 and T.nwqid ~= 0 then
					T:error("not found")
					return
				end
				-- Otherwise it was a partial walk, which
				-- does not draw error and does not set up
				-- a new fid either.
			else
				-- Successful walk
				if #wqid == 0 then
					newstate.qid = T.state.qid
				else
					newstate.qid = wqid[#wqid]
				end
				if not T.move then
					S.fids[T.newfid] = newstate
				end
			end
			respond(T, S, {wqid = wqid})
		end
		S.walk(T)
	end;
	[no.Tclunk] = function(T, S)
		if S.clunk
		then S.clunk(T)
		else T:respond()
		end
		S.fids[T.fid] = nil
	end;
	[no.Tremove] = function(T, S)
		if S.remove
		then S.remove(T)
		else T:error("remove not implemented")
		end
		S.fids[T.fid] = nil
	end;
	[no.Tstat] = function(T, S)
		if not S.stat
		then T:error("stat not implemented"); return
		end
		T.respond = function(_, statlike)
			respond(T, S, {stat = statlike})
		end
		S.stat(T)
	end;
	[no.Twstat] = function(T, S)
		if not S.wstat
		then T:error("wstat not implemented"); return
		end
		S.wstat(T)
	end;
	[no.Topen] = function(T, S)
		local st = T.state
		local isdir = st.qid.type & no.QTDIR > 0
		if st.mode then
			T:error(no.Ebotch); return
		elseif isdir then
			if T.mode & no.OTRUNC > 0 then
				T.mode = T.mode | no.OWRITE
			end
			if T.mode&3 ~= no.OREAD then
				T:error("permission denied"); return
			end
		end
		T.respond = function(_, qid, iounit)
			respond(T, S, {
				qid = qid and qid or T.state.qid,
				iounit = iounit and iounit or S.iounit
			})
			T.state.mode = T.mode
		end
		if isdir and S.list then
			T.state.listfn = co.create(listdir)
			T:respond(st.qid)
		elseif S.open then
			S.open(T)
		else
			T:respond()
		end
	end;
	[no.Tcreate] = function(T, S)
		if not S.create
		then T:error("create not implemented"); return
		end
		local isdir = T.state.qid.type & no.QTDIR > 0
		if T.state.mode then
			T:error(no.Ebotch); return
		elseif not isdir then
			T:error("create in a non-directory"); return
		end
		T.respond = function(_, qid, iounit)
			respond(T, S, {
				qid = qid,
				iounit = iounit and iounit or S.iounit
			})
			T.state.mode = T.mode
		end
		S.create(T)
	end;
	[no.Tread] = function(T, S)
		if not (S.read or S.list) then
			T:error("read prohibited"); return
		end
		local m = T.state.mode and T.state.mode & 3
		if not m
		or not (m == no.OREAD or m == no.ORDWR or m == no.OEXEC)
		then
			T:error(no.Ebotch); return
		end
		T.count = min(T.count, S.iounit)
		T.respond = function(_, data)
			respond(T, S, {data = data and data or ""})
		end
		if T.state.listfn then
			local ok, data = co.resume(T.state.listfn, T, S)
			if not ok then
				T:error(data)
				T.state.listfn = nil
			elseif data == "done" then
				T:respond()
				T.state.listfn = nil
			else
				T:respond(data)
			end
		else
			S.read(T)
		end
	end;
	[no.Twrite] = function(T, S)
		if not S.write then
			T:error("write prohibited"); return
		end
		local m = T.state.mode and T.state.mode & 3
		if not m
		or not (m == no.OWRITE or m == no.ORDWR)
		or T.state.qid.type & no.QTDIR > 0
		then
			T:error(no.Ebotch); return
		end
		T.count = min(T.count, S.iounit)
		T.respond = function(_, count)
			respond(T, S, {count = count and count or 0})
		end
		S.write(T)
	end;
}

function no.server(S)
	assert(type(S) == "table")
	assert(S.reader and S.writer, "server i/o functions missing")
	assert(S.attach and S.walk, "missing required handlers")

	S.fids = {}
	S.tags = {}
	S.msize = (S.msize and S.msize or 8192) + 24
	S.iounit = S.msize - 24
	return function()
		local T = no.decode(S.reader)
		-- Generic response.  Most transactions define
		-- custom versions to handle dependent response
		-- parameters, to properly implement the protocol,
		-- to maintain session state, and similar.
		T.respond = function(self, R)
			respond(self, S, R)
		end
		T.error = function(self, message)
			respond(self, S, {error = message})
		end
		--
		if T.tag == no.NOTAG then
			if T.type ~= no.Tversion then
				T:error(no.Ebotch); return false
			end
		else
			if S.tags[T.tag] then
				T:error("duplicate tag"); return false
			end
			S.tags[T.tag] = T
		end
		--
		T.state = S.fids[T.fid]
				if S.trace then trace(T, S) end
		dispatch[T.type](T, S)
				if S.trace and T.response then trace(T.response, S) end
	end
end



-- Tree helper

local function qidgen()
	local path = -1
	return function()
		path = path + 1
		return path
	end
end
local qidnext = qidgen()
function no.qid(type, path, vers)
	return {
		type = type and type or no.QTFILE,
		path = path and type or qidnext(),
		vers = vers and vers or 0
	}
end

local function extend(t, ...)
	assert(type(t) == "table")
	for i = 1, select("#", ...) do
		local et = select(i, ...); assert(type(et) == "table")
		for k, v in pairs(et) do
			if not t[k] then t[k] = v end
		end
	end
	return t
end

local function lexwalk(dir, name)
	local tree = dir.tree
	local path = dir.path
	local try
	if name == ".." then
		if path == "/" then return dir end
		path = path:gsub("/[^/]+/?$", "")
		name = ""
	end
	try = (path:match("/$") and path or (path .. "/")) .. name
	if tree[try] then
		return tree[try]
	end
	try = try .. "/"
	if tree[try] then
		return tree[try]
	end
	return false
end

local protofile = {
	atime = os.time(),
	mtime = os.time(),
	uid = "glenda",
	gid = "glenda",
	muid = "glenda",
	length = 0,

	is = function(self, what)
		if what == "file" then
			return self.qid.type & no.QTDIR == 0
		elseif what == "dir" then
			return self.qid.type & no.QTDIR > 0
		end
	end;
	walk = function(self, wname)
		local f = self
		local wqid = {}
		for _, name in ipairs(wname) do
			f = lexwalk(f, name)
			if not f then
				return nil, wqid
			end
			table.insert(wqid, f.qid)
		end
		return f, wqid
	end;
	kids = function(self)
		local t = {}
		for k, v in pairs(self.tree) do
			if k:match('^' ..self.path.. '[^/]+/?$') then
				table.insert(t, v)
			end
		end
		return t
	end;
}
local treemt = {
	__newindex = function(t, k, v)
		local f = extend(v, protofile)
		f.tree = t
		f.path = k
		if k:match("/$") then
			f.name = f.name == "/" and "/" or k:gsub("^.*/([^/]+)/$", "%1")
			f.qid = f.qid or no.qid(no.QTDIR)
			f.mode = f.mode or tonumber("755", 8) | no.DMDIR
		else
			f.name = k:gsub("^.*/(.+)$", "%1")
			f.qid = f.qid or no.qid()
			f.mode = f.mode or tonumber("644", 8)
		end
		rawset(t, k, f)
	end;
}
function no.tree()
	local tree = {}
	return setmetatable(tree, treemt)
end

return no
