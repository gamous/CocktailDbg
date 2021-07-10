all:
	gcc ct_dbg.c core.c target_file.c \
        breakpoint.c syscall_tbl.c    \
		interactive.c plugin.c disasm.c -o ../bin/ct_dbg -lcapstone
debug:
	gcc ct_dbg.c core.c target_file.c \
        breakpoint.c syscall_tbl.c    \
		interactive.c plugin.c disasm.c -o ../bin/ct_dbg_t -g -lcapstone
debug_bp:
	gcc -D DEBUG_BP breakpoint.c target_file.c  breakpoint_test.c core.c -o ../bin/bp_test -g

debug_file:
	gcc target_file.c target_file_test.c core.c -o ../bin/target_file_test -g
