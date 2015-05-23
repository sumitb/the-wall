# the-wall
Advanced project under Prof. Michalis Polychronakis

Project Proposal: https://www.dropbox.com/s/szawo36bn61xe44/Project_Proposal.docx?dl=0
Results: https://www.dropbox.com/s/2pw21ams84mvyzw/Results.xlsx?dl=0

Pre-requisities: Detours Express 3.0, Visual Studio 2013
Download Link: http://research.microsoft.com/en-us/downloads/d36340fb-4d3c-4ddd-bf5b-1db25d03713d/default.aspx
Detours tutorial: http://resources.infosecinstitute.com/api-hooking-detours/

Before moving to detours we tried to use Microsoft Shims framework for hooking into Win32/64 API functions.
Shims tutorial: http://www.ibm.com/developerworks/rational/library/shims-incompatible-runtime-environments/

1. Fork/clone this repo.
2. Build the cse523.sln
3. Run injector.exee tool <Usage: injector.exe <PID of process> >

Note: dll path related hard-codings exist, please modify them for now. I'll fix it later.
