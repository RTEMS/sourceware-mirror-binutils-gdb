#name: check that Armv8-R system registers are rejected without -march=armv8-r
#as: -menable-sysreg-checking
#source: v8-r-sysregs.s
#error_output: v8-r-sysregs-need-arch.l
