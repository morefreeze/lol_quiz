[General]
SyntaxVersion=2
BeginHotkey=121
BeginHotkeyMod=0
PauseHotkey=0
PauseHotkeyMod=0
StopHotkey=123
StopHotkeyMod=0
RunOnce=1
EnableWindow=
MacroID=e96a33e0-38fe-4dff-96f9-12064e07a452
Description=lolking
Enable=1
AutoRun=0
[Repeat]
Type=2
Number=10860
[SetupUI]
Type=2
QUI=
[Relative]
SetupOCXFile=
[Comment]

[Script]
wd = Plugin.Window.Find("SDL_app", "5554:q")
If wd > 0 Then 
	If "00AEFF" = Plugin.Bkgnd.GetPixelColor(wd, 300, 300) Then
		Call Plugin.Bkgnd.LeftClick(wd, 300, 425)
	Else 
		choice = Int((4 * Rnd) + 0)
		Call Plugin.Bkgnd.LeftClick(wd, 300, 325 + choice * 100)
		Call Plugin.Bkgnd.LeftClick(wd, 250, 750)
	End If

End If
Delay(7000)