CC_64=x86_64-w64-mingw32-gcc
peparser:
	$(CC_64) pe_parser.c -o pe_parser.exe