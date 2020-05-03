Set objSession = CreateObject("Microsoft.Update.Session")

Set objSearcher = objSession.CreateUpdateSearcher

Set colHistory = objSearcher.QueryHistory(0, 999)

dtMin = DateSerial(2000, 1, 1)

For Each objEntry in colHistory
	dt = objEntry.Date
	if (dtMin < dt) then
		dtMin = dt
	end if
Next

Wscript.Echo dtMin

diff = DateDiff("d", dtMin, Now)

if (diff < 90) then
	Wscript.Echo "OK"
    WScript.Quit(0)
end if

WScript.Quit(1)
Wscript.Echo "NG"


