On Error Resume Next

Set colItems = CreateObject("WbemScripting.SWbemLocator") _
              .ConnectServer(".", "root\SecurityCenter2") _
              .ExecQuery("Select * from AntiVirusProduct")

If Err.Number <> 0 Then
  WScript.Echo "NG CreateObject"
  WScript.Quit(1)
end if

ok = False

For Each oItem In colItems
	statestr = Hex("" & oItem.productState)
	
	length = 8
	statestr = Replace(Space(length - Len(statestr)) & statestr, Space(1), "0")
	
	WScript.Echo statestr
	
	active_state = Mid(statestr, 5, 1)
	
	update_state = Mid(statestr, 7, 2)
	
	if (active_state = "1") then
	  if (update_state = "00") then
	    ok = True
	  end if
	end if
Next

if ok then
  WScript.Echo "OK"
  WScript.Quit(0)
else
  WScript.Echo "NG"
  WScript.Quit(1)
end if


