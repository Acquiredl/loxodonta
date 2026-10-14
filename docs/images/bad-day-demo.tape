# The README's first picture as a vhs tape (https://github.com/charmbracelet/vhs):
# the staged session's report, a clean verdict, one word of entry 3
# rewritten, and the verdict that names it.
# Re-record with:  vhs docs/images/bad-day-demo.tape   (needs vhs, ttyd, ffmpeg,
# and a Chromium that prints its DevTools line on stderr: Edge 155 does not,
# so point the recorder at one with ROD=bin=<path to chrome.exe>).
# Run it from a folder that holds only a copy of loxodonta.py and, under
# docs/demo/, a copy of bad-day-session.jsonl (the sed edits that copy), so
# no real path or name reaches a frame; the prompt is set to "$ " off camera
# for the same reason.
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
Set Height 380
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
Sleep 1.5s

Type "sed -i 's/Read: .env/Read: README.md/' docs/demo/bad-day-session.jsonl   # the cover-up"
Enter
Sleep 1.2s

Type "python loxodonta.py verify --log docs/demo/bad-day-session.jsonl"
Enter
Sleep 3s
