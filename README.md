# the-wall
Advanced project under Prof. Michalis Polychronakis

Results: https://www.dropbox.com/s/2pw21ams84mvyzw/Results.xlsx?dl=0

Pre-requisities: Detours Express 3.0, Visual Studio 2013
Download Link: http://research.microsoft.com/en-us/downloads/d36340fb-4d3c-4ddd-bf5b-1db25d03713d/default.aspx
Detours tutorial: http://resources.infosecinstitute.com/api-hooking-detours/

Before moving to detours we tried to use Microsoft Shims framework for hooking into Win32/64 API functions.
Shims tutorial: http://www.ibm.com/developerworks/rational/library/shims-incompatible-runtime-environments/

1. Fork/clone dllinject branch of this repo.
2. Build the cse523.sln
3. This will build detoured.dll and injector.exe which will be used further.
4. All python scripts exist in the Experiments folder.
	> pdfget.py - Use this script to download all pdfs from a root url like gutenberg project, etc.
	> run.py - This is the main script which will use executables generated in the above step to run on any Application. The default testing application is Adobe Reader DC. Please install it accordingly and ensure the path is valid. This will generate a temorary file named as MyLogFile.txt in the Release folder.
	> log_filter.py - This generates the graph, collates the data in the visual format and store log files in the Experiments folder. 

Note: dll path related hard-codings exist, please modify them for now.
