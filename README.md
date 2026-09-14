# Advanced Turbo Flasher Emulator

This project emulates communication between box and ATF tools so latest software can be used with v9/v10 firmware.

It only emulates .rsa file for software to show that box is activated, but it does not make boxes with v11 firmware work, if you have
valid .rsa file for your box, emulator will use it instead of generating dummy file.

Also it includes bypass for Themida VM checks, so you can use any software version on virtual machine.

For now the only option is to downgrade box firmware, or hope that someday server will be online.

More findings about requests encryption in [Findings](findings/README.md).

## Build Environment

This project is built using Microsoft Visual Studio 6.0 (VS6).

Emulator project compiles into DLL that is injected using emulator injector project.

## Acknowledgements

Portions of the reverse-engineering analysis, particularly the identification and understanding of hashing functions, were assisted by AI tools.