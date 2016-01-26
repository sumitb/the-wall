class LogFilter(object):
	"""docstring for LogFilter"""
	def __init__(self):
		
		# Log File path
		self.logfile = r'C:\Users\sbindal\vs2013\Projects\cse523\Release\MyLogFile.txt'

		# List of function calls
		self.functions = [r'GetProcAddress',
					r'LoadLibrary',
					r'LoadLibraryEx',
					r'VirtualAlloc',
					r'VirtualAllocEx',
					r'VirtualProtect',
					r'VirtualProtectEx']

		# Resultant dictionary
		self.api = {}

	def main(self):
		# import pefile as pe
		import numpy as np
		import matplotlib.pyplot as plt
		from itertools import groupby

		# Open log file
		with open(self.logfile) as f:
			data = f.read()
			dataList = data.strip().split('\n')
			startTime = int(dataList[0].strip().split(' ')[-1])
			endTime = (int(dataList[-1].strip().split(' ')[-1]) - startTime) / 1000
			
			# Remove first and last element and rejoin
			dataList.pop()
			data = '\n'.join(dataList[1:])
			data = data.split('n00b')

			for stack in data:
				stack = stack.strip().split('\n')
				if stack == ['']:
					continue
				functionName = stack[0].split('_')[0]
				stackTime = (int(stack[2]) - startTime) / 1000
				stackTrace = stack[3:]

				# filter only function calls
				stackTrace[:] = [''.join(line.split('-')[0].split(':')[1:]).strip() for line in stackTrace]
				stackTrace[:] = [line for line in stackTrace if line != 'printStack']
				stackTrace[:] = [line for line in stackTrace if line.lower().find('detour') == -1]
				stackTrace[:] = [line[len('Mine_'):] if line.startswith('Mine_') else line for line in stackTrace]
				stackTrace[:] = [line[0] for line in groupby(stackTrace)]

				if functionName.strip():
					if functionName not in self.api:
						self.api[functionName] = [1, [stackTrace], [stackTime]]
					else:
						self.api[functionName][0] = self.api[functionName][0] + 1
						self.api[functionName][2].append(stackTime)
						if stackTrace not in self.api[functionName][1]: 
							self.api[functionName][1].append(stackTrace)
						# if stackTime > self.api[functionName][2]: 
							# self.api[functionName][2].append(stackTime)
		
		plt.figure(1)
		plotnum = 0
		f, axarr = plt.subplots(len(self.api), sharex=True)
		for k, v in self.api.iteritems():
			print k + ' total detoured calls: ' + str(v[0])
			print 'Last accessed at: ' + str(max(v[2]))
			data = [0] + v[2] + [endTime]
			axarr[plotnum].set_ylabel(k)
			axarr[plotnum].hist(data, bins=np.arange(min(data), max(data)+1)) # plotting the column as histogram 
			
			for j, st in enumerate(v[1]):
				print 'Stack Trace ' + str(j+1) + ' :'
				for i, line in enumerate(st):
					print str(len(st)-i-1) + '. ' + line
				print 
			plotnum = plotnum + 1
		plt.xlabel('time (s)')
		plt.show()

if __name__ == '__main__':
	lofi = LogFilter()
	lofi.main()
