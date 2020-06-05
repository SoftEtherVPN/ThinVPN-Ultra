On Error Resume Next


Set objSession = CreateObject("Microsoft.Update.Session")

If Err.Number <> 0 Then
  WScript.Echo "NG CreateObject"
  WScript.Quit(1)
end if

Set objSearcher = objSession.CreateUpdateSearcher

If Err.Number <> 0 Then
  WScript.Echo "NG CreateObject"
  WScript.Quit(1)
end if

Set colHistory = objSearcher.QueryHistory(0, 999)

If Err.Number <> 0 Then
  WScript.Echo "NG CreateObject"
  WScript.Quit(1)
end if

dtMin = DateSerial(2000, 1, 1)

For Each item in colHistory
	if item.ResultCode = 2 then
		if InStr(item.Title, "(KB") then
			is_for_windows = false

			if InStr(item.Title, "Windows") then
				is_for_windows = true
			end if

			For J = 0 To item.categories.Count-1
				Set category = item.categories.Item(J)
				if (Instr(category.Name, "Windows")) then
					is_for_windows = true
				end if
			next

			if InStr(item.Title, "KB890830") then
				is_for_windows = false
			end if

			if (is_for_windows) then
				'Wscript.Echo "" & item.Date & " " & item.Title
				dt = item.Date
				if (dtMin < dt) then
					dtMin = dt
				end if
			end if
		end if
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


