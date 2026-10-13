# The README's staged session as a vhs tape (https://github.com/charmbracelet/vhs).
# Re-record with:  vhs docs/images/bad-day-demo.tape   (needs vhs, ttyd, ffmpeg)
# Run it from a folder that holds only a copy of loxodonta.py and, under
# docs/demo/, a copy of bad-day-session.jsonl, so no real path or name
# reaches a frame; the prompt is set to "$ " off camera for the same reason.
# The commands are the README's, character for character: the text block
# stays the reproduction, this is only the picture of it.
#
# Windows note. ttyd starts the shell with CreateProcess, which searches
# System32 before PATH, so `Set Shell "bash"` lands on WSL's bash.exe, and
# vhs refuses an absolute shell path. The tape therefore starts PowerShell and
# hops into Git Bash while hidden. On Linux or macOS, replace the Set Shell
# line with `Set Shell "bash"` and delete the hop (the first Type/Enter/Sleep
# inside Hide).

Output bad-day-demo.gif

Set Shell "powershell"
Set FontSize 15
Set Width 1420
Set Height 340
Set Padding 24
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "& 'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc"
Enter
Sleep 1.5s
Type "export PS1='$ ' PYTHONIOENCODING=utf-8; clear"
Enter
Sleep 500ms
Show

Type "python loxodonta.py report --log docs/demo/bad-day-session.jsonl"
Enter
Sleep 4s

Type "python loxodonta.py verify --log docs/demo/bad-day-session.jsonl"
Enter
Sleep 3s
