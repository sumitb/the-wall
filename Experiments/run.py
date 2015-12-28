# Injector application path
# Usage: injector.exe <process pid>
inject = r'C:\Users\sbindal\vs2013\Projects\cse523\Release\injector.exe'

# List of processes
processes = [r'C:\Program Files (x86)\Firefox Developer Edition\firefox.exe',
			r'C:\Program Files (x86)\Internet Explorer\iexplore.exe',
			r'C:\Program Files (x86)\Brackets\Brackets.exe',
			r'C:\Program Files (x86)\PuTTY\putty.exe',
			r'C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\devenv.exe',
			r'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
			r'C:\Program Files (x86)\Battle.net\Battle.net.5765\Battle.net.exe',
			r'C:\Program Files (x86)\Steam\Steam.exe',
			r'C:\Program Files (x86)\VideoLAN\VLC\vlc.exe',
			r'C:\Program Files (x86)\Windows Media Player\wmplayer.exe',
			r'C:\Program Files (x86)\Adobe\Reader 11.0\Reader\AcroRd32.exe']

def _main():
	import subprocess, time
	processes = [r'C:\Program Files (x86)\Windows Media Player\wmplayer.exe']
	for process in processes:
		pid = subprocess.Popen([process, ""]).pid
		# Sleep for few seconds to attach debugger
		time.sleep(5)
		# Inject hook.dll using injector.exe
		injectPID = subprocess.Popen([inject, str(pid)]).pid
		print pid, injectPID


if __name__ == '__main__':
	_main()
