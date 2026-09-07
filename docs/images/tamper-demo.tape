# The README's tamper demo as a vhs tape (https://github.com/charmbracelet/vhs).
# Re-record with:  vhs docs/images/tamper-demo.tape   (needs vhs, ttyd, ffmpeg)
# Run it from a folder that holds only a copy of loxodonta.py, so no real path
# or name reaches a frame; the prompt is set to "$ " off camera for the same
# reason. The commands are the README's demo block, character for character:
# the text block stays the reproduction, this is only the picture of it.
#
# Windows note. ttyd starts the shell with CreateProcess, which searches
# System32 before PATH, so `Set Shell "bash"` lands on WSL's bash.exe, and
# vhs refuses an absolute shell path. The tape therefore starts PowerShell and
# hops into Git Bash while hidden. On Linux or macOS, replace the Set Shell
# line with `Set Shell "bash"` and delete the hop (the first Type/Enter/Sleep
# inside Hide).

Output tamper-demo.gif

Set Shell "powershell"
Set FontSize 18
Set Width 1100
Set Height 560
Set Padding 24
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "& 'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc"
Enter
Sleep 1.5s
Type "export PS1='$ '; clear"
Enter
Sleep 500ms
Show

Type "python loxodonta.py init"
Enter
Sleep 1s

Type 'python loxodonta.py log --actor claude-code --action "Edit: deploy.yml"'
Enter
Sleep 1s

Type 'python loxodonta.py log --actor claude-code --action "Bash: git push origin main"'
Enter
Sleep 1s

Type "python loxodonta.py verify"
Enter
Sleep 1.5s

Type "sed -i 's/Edit: deploy.yml/Edit: README.md/' receipts.jsonl   # the cover-up"
Enter
Sleep 1.2s

Type "python loxodonta.py verify"
Enter
Sleep 3s
