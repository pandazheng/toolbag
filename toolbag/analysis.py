# analysis.py
#
# for public release, 2012
#
# Kelly Lum

import idautils
import idaapi
import idc

class myxrange(object):
    def __init__(self, a1, a2=None, step=1):
        if step == 0:
            raise ValueError("arg 3 must not be 0")
        if a2 is None:
            a1, a2 = 0, a1
        if (a2 - a1) % step != 0:
            a2 += step - (a2 - a1) % step
        if cmp(a1, a2) != cmp(0, step):
            a2 = a1
        self.start, self.stop, self.step = a1, a2, step

    def __iter__(self):
        n = self.start
        while cmp(n, self.stop) == cmp(0, self.step):
            yield n
            n += self.step

    def __repr__(self):
        return "MyXRange(%d,%d,%d)" % (self.start, self.stop, self.step)

    # NB: len(self) will convert this to an int, and may fail
    def __len__(self):
        return (self.stop - self.start)//(self.step)

    def __getitem__(self, key):
        if key < 0:
            key = self.__len__() + key
            if key < 0:
                raise IndexError("list index out of range")
            return self[key]
        n = self.start + self.step*key
        if cmp(n, self.stop) != cmp(0, self.step):
            raise IndexError("list index out of range")
        return n

    def __reversed__(self):
        return MyXRange(self.stop-self.step, self.start-self.step, -self.step)

    def __contains__(self, val):
        if val == self.start: return cmp(0, self.step) == cmp(self.start, self.stop)
        if cmp(self.start, val) != cmp(0, self.step): return False
        if cmp(val, self.stop) != cmp(0, self.step): return False
        return (val - self.start) % self.step == 0

class properties():

	def __init__(self, addr):
		self.addr = addr

	def funcProps(self): #build a dictionary using all the functions we've got
		props = {}
		props['isLeaf'] 	 = self.isLeaf()		
		props['numArgs'] 	 = self.argCount()
		props['xrefsTo'] 	 = self.countXrefsTo()
		props['isExport'] 	 = self.isExport()
		props['funcSize'] 	 = self.functionSize()	
		props['hasCookie'] 	 = self.hasCookie()	
		props['xrefsFrom'] 	 = self.countXrefsFrom()
		props['numBlocks'] 	 = self.countBlocks()
		props['numChunks'] 	 = self.countChunks()
		props['isRecursive'] = self.isRecursive()
		
		return props

	# needs some finesse, but... it's a steak...
	def hasCookie(self):
		end   = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END)
		start = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)

		count = 0
		while((start != end) and (start != idc.BADADDR)):
			line = idc.GetDisasm(start)
			if line.startswith('xor'):
				if 'ebp' in line: 
					return True
			start = idc.NextAddr(start)
			count += 1
			# security cookie check is usually at beginning of function (unless some crazy-ass prologue)
			if (count > 20): return False
		return False


	def argCount(self): 
		end       = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END)
		start     = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)
		frame     = idc.GetFrame(start)
		localv    = idc.GetFunctionAttr(self.addr, idc.FUNCATTR_FRSIZE)	
		frameSize = idc.GetFrameSize(start) #idc.GetStrucSize(frame)


		reg_off = 0
		local_count = 0
		arg_count = 0
		sid = idc.GetFrame(self.addr)
		if sid:
			firstM = idc.GetFirstMember(sid)
			lastM = idc.GetLastMember(sid)
			arg_count = 0

			if lastM - firstM > 0x1000:
				return

			for i in myxrange(firstM, lastM):
				mName = idc.GetMemberName(sid, i)
				mSize = idc.GetMemberSize(sid, i)
				mFlag = idc.GetMemberFlag(sid, i)
				off = idc.GetMemberOffset(sid, mName)
				#print "%s: %d, %x, off=%x" % (mName, mSize, mFlag, off)

				if mName == " r":
					reg_off = off

			# XXX: just store the data, dont loop twice.
			for i in myxrange(firstM, lastM):
				mName = idc.GetMemberName(sid, i)
				mSize = idc.GetMemberSize(sid, i)
				mFlag = idc.GetMemberFlag(sid, i)
				off = idc.GetMemberOffset(sid, mName)

				if off <= reg_off:
					local_count += 1
				elif off > reg_off and reg_off != 0:
					arg_count += 1


			if arg_count > 0:
				return arg_count / 4
			elif arg_count == 0:
				return 0

		# offset to return
		try: 
			ret = idc.GetMemberOffset(frame, " r") 
		except:
			if frameSize > localv:
				return (frameSize - localv) / 4
			# error getting function frame (or none exists)
			return -1 
 
		if (ret < 0): 
			if frameSize > localv:
				return (frameSize - localv) / 4
			return -1 

		firstArg = ret + 4 
		args  = frameSize - firstArg	
		numArgs = args / 4

		return numArgs

	def functionSize(self):
		return idc.GetFunctionAttr(self.addr, idc.FUNCATTR_END) - idc.GetFunctionAttr(self.addr, idc.FUNCATTR_START)

	def isExport(self):
		entries = idautils.Entries()

		for entry in entries:
			if self.addr in entry: return True
			
	 	return False

	def isLeaf(self):
		if (self.countXrefsFrom() == 0):	return True
		return False

	def isRecursive(self):
		return (self.addr in list(idautils.XrefsFrom(self.addr)))

	def countBlocks(self):
		try:
			res = len(list(idaapi.FlowChart(idaapi.get_func(self.addr))))
			return res
		except:
			return 0

	def countXrefsTo(self):
		return len(list(idautils.XrefsFrom(self.addr)))

	def countXrefsFrom(self):
		return len(list(idautils.XrefsTo(self.addr)))

	def countChunks(self): 
		return len(list(idautils.Chunks(self.addr)))

class search():
	def __init__(self, engine):
		#engine is a user-provided function that performs matching
		self.engine = engine  

	def matches(self, func_data):
		#return a subset of func_data that satisfies the matching engine
		matches = {}
		for func, func_info in func_data.iteritems():
			if func_info['attr']:
				exec(self.engine)
				res = myengine(func_info['attr'])
				if res: 
					matches[func] = func_info
		return matches	

		






