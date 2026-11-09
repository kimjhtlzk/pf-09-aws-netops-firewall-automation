# Record with: vhs docs/assets/demo.tape (needs netops on PATH)
# Runs against a fake moto environment. No credentials, and nothing local is visible.
Output docs/assets/demo.gif
Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 15
Set Width 1200
Set Height 760
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 35ms

Hide
Type "export HOME=$(mktemp -d) PS1='$ '; clear"
Enter
Sleep 500ms
Show

Type "netops confirm --demo"
Enter
Sleep 6s
Type "clear; netops modify --demo"
Enter
Sleep 7s
