# SkillSentry demo recording — renders docs/demo.gif
#
# Install VHS once:  https://github.com/charmbracelet/vhs  (winget/scoop, or WSL/Git Bash).
# Then from the repo root:
#     pip install -e .          # so the `skillsentry` command exists
#     vhs docs/demo.tape        # produces docs/demo.gif
#
# Embed it near the top of README.md with:  ![SkillSentry demo](docs/demo.gif)

Output docs/demo.gif

Set FontSize 16
Set Width 1120
Set Height 860
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 55ms

Type "skillsentry scan fixtures/malicious/file_helper/SKILL.md"
Sleep 500ms
Enter
Sleep 8s
