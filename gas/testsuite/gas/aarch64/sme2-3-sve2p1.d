#as: -march=armv8-a+sve2p1
#objdump: -dr

[^:]+:     file format .*


[^:]+:

[^:]+:
[^:]+:	a0406000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a0406000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a0406000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a040601e 	ld1d	{z30\.d-z31\.d}, pn8/z, \[x0\]
[^:]+:	a0407c00 	ld1d	{z0\.d-z1\.d}, pn15/z, \[x0\]
[^:]+:	a04063c0 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x30\]
[^:]+:	a04063e0 	ld1d	{z0\.d-z1\.d}, pn8/z, \[sp\]
[^:]+:	a0486000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, #-16, mul vl\]
[^:]+:	a0476000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, #14, mul vl\]
[^:]+:	a04b756c 	ld1d	{z12\.d-z13\.d}, pn13/z, \[x11, #-10, mul vl\]
[^:]+:	a040e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e01c 	ld1d	{z28\.d-z31\.d}, pn8/z, \[x0\]
[^:]+:	a040fc00 	ld1d	{z0\.d-z3\.d}, pn15/z, \[x0\]
[^:]+:	a040e3c0 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x30\]
[^:]+:	a040e3e0 	ld1d	{z0\.d-z3\.d}, pn8/z, \[sp\]
[^:]+:	a048e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, #-32, mul vl\]
[^:]+:	a047e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, #28, mul vl\]
[^:]+:	a045ee28 	ld1d	{z8\.d-z11\.d}, pn11/z, \[x17, #20, mul vl\]
[^:]+:	a0016000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0016000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0016000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001601e 	ld1d	{z30\.d-z31\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0017c00 	ld1d	{z0\.d-z1\.d}, pn15/z, \[x0, x1, lsl #3\]
[^:]+:	a00163c0 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x30, x1, lsl #3\]
[^:]+:	a00163e0 	ld1d	{z0\.d-z1\.d}, pn8/z, \[sp, x1, lsl #3\]
[^:]+:	a01e6000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, x30, lsl #3\]
[^:]+:	a01f6000 	ld1d	{z0\.d-z1\.d}, pn8/z, \[x0, xzr, lsl #3\]
[^:]+:	a003674e 	ld1d	{z14\.d-z15\.d}, pn9/z, \[x26, x3, lsl #3\]
[^:]+:	a001e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e01c 	ld1d	{z28\.d-z31\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001fc00 	ld1d	{z0\.d-z3\.d}, pn15/z, \[x0, x1, lsl #3\]
[^:]+:	a001e3c0 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x30, x1, lsl #3\]
[^:]+:	a001e3e0 	ld1d	{z0\.d-z3\.d}, pn8/z, \[sp, x1, lsl #3\]
[^:]+:	a01ee000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, x30, lsl #3\]
[^:]+:	a01fe000 	ld1d	{z0\.d-z3\.d}, pn8/z, \[x0, xzr, lsl #3\]
[^:]+:	a001ef68 	ld1d	{z8\.d-z11\.d}, pn11/z, \[x27, x1, lsl #3\]
[^:]+:	a0406001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a0406001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a0406001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0\]
[^:]+:	a040601f 	ldnt1d	{z30\.d-z31\.d}, pn8/z, \[x0\]
[^:]+:	a0407c01 	ldnt1d	{z0\.d-z1\.d}, pn15/z, \[x0\]
[^:]+:	a04063c1 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x30\]
[^:]+:	a04063e1 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[sp\]
[^:]+:	a0486001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, #-16, mul vl\]
[^:]+:	a0476001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, #14, mul vl\]
[^:]+:	a04b756d 	ldnt1d	{z12\.d-z13\.d}, pn13/z, \[x11, #-10, mul vl\]
[^:]+:	a040e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0\]
[^:]+:	a040e01d 	ldnt1d	{z28\.d-z31\.d}, pn8/z, \[x0\]
[^:]+:	a040fc01 	ldnt1d	{z0\.d-z3\.d}, pn15/z, \[x0\]
[^:]+:	a040e3c1 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x30\]
[^:]+:	a040e3e1 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[sp\]
[^:]+:	a048e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, #-32, mul vl\]
[^:]+:	a047e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, #28, mul vl\]
[^:]+:	a045ee29 	ldnt1d	{z8\.d-z11\.d}, pn11/z, \[x17, #20, mul vl\]
[^:]+:	a0016001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0016001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0016001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001601f 	ldnt1d	{z30\.d-z31\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a0017c01 	ldnt1d	{z0\.d-z1\.d}, pn15/z, \[x0, x1, lsl #3\]
[^:]+:	a00163c1 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x30, x1, lsl #3\]
[^:]+:	a00163e1 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[sp, x1, lsl #3\]
[^:]+:	a01e6001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, x30, lsl #3\]
[^:]+:	a01f6001 	ldnt1d	{z0\.d-z1\.d}, pn8/z, \[x0, xzr, lsl #3\]
[^:]+:	a003674f 	ldnt1d	{z14\.d-z15\.d}, pn9/z, \[x26, x3, lsl #3\]
[^:]+:	a001e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001e01d 	ldnt1d	{z28\.d-z31\.d}, pn8/z, \[x0, x1, lsl #3\]
[^:]+:	a001fc01 	ldnt1d	{z0\.d-z3\.d}, pn15/z, \[x0, x1, lsl #3\]
[^:]+:	a001e3c1 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x30, x1, lsl #3\]
[^:]+:	a001e3e1 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[sp, x1, lsl #3\]
[^:]+:	a01ee001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, x30, lsl #3\]
[^:]+:	a01fe001 	ldnt1d	{z0\.d-z3\.d}, pn8/z, \[x0, xzr, lsl #3\]
[^:]+:	a001ef69 	ldnt1d	{z8\.d-z11\.d}, pn11/z, \[x27, x1, lsl #3\]
[^:]+:	a0606000 	st1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a0606000 	st1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a0606000 	st1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a060601e 	st1d	{z30\.d-z31\.d}, pn8, \[x0\]
[^:]+:	a0607c00 	st1d	{z0\.d-z1\.d}, pn15, \[x0\]
[^:]+:	a06063c0 	st1d	{z0\.d-z1\.d}, pn8, \[x30\]
[^:]+:	a06063e0 	st1d	{z0\.d-z1\.d}, pn8, \[sp\]
[^:]+:	a0686000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, #-16, mul vl\]
[^:]+:	a0676000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, #14, mul vl\]
[^:]+:	a06b756c 	st1d	{z12\.d-z13\.d}, pn13, \[x11, #-10, mul vl\]
[^:]+:	a060e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e01c 	st1d	{z28\.d-z31\.d}, pn8, \[x0\]
[^:]+:	a060fc00 	st1d	{z0\.d-z3\.d}, pn15, \[x0\]
[^:]+:	a060e3c0 	st1d	{z0\.d-z3\.d}, pn8, \[x30\]
[^:]+:	a060e3e0 	st1d	{z0\.d-z3\.d}, pn8, \[sp\]
[^:]+:	a068e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, #-32, mul vl\]
[^:]+:	a067e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, #28, mul vl\]
[^:]+:	a065ee28 	st1d	{z8\.d-z11\.d}, pn11, \[x17, #20, mul vl\]
[^:]+:	a0216000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0216000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0216000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021601e 	st1d	{z30\.d-z31\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0217c00 	st1d	{z0\.d-z1\.d}, pn15, \[x0, x1, lsl #3\]
[^:]+:	a02163c0 	st1d	{z0\.d-z1\.d}, pn8, \[x30, x1, lsl #3\]
[^:]+:	a02163e0 	st1d	{z0\.d-z1\.d}, pn8, \[sp, x1, lsl #3\]
[^:]+:	a03e6000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, x30, lsl #3\]
[^:]+:	a03f6000 	st1d	{z0\.d-z1\.d}, pn8, \[x0, xzr, lsl #3\]
[^:]+:	a023674e 	st1d	{z14\.d-z15\.d}, pn9, \[x26, x3, lsl #3\]
[^:]+:	a021e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e01c 	st1d	{z28\.d-z31\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021fc00 	st1d	{z0\.d-z3\.d}, pn15, \[x0, x1, lsl #3\]
[^:]+:	a021e3c0 	st1d	{z0\.d-z3\.d}, pn8, \[x30, x1, lsl #3\]
[^:]+:	a021e3e0 	st1d	{z0\.d-z3\.d}, pn8, \[sp, x1, lsl #3\]
[^:]+:	a03ee000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, x30, lsl #3\]
[^:]+:	a03fe000 	st1d	{z0\.d-z3\.d}, pn8, \[x0, xzr, lsl #3\]
[^:]+:	a021ef68 	st1d	{z8\.d-z11\.d}, pn11, \[x27, x1, lsl #3\]
[^:]+:	a0606001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a0606001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a0606001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0\]
[^:]+:	a060601f 	stnt1d	{z30\.d-z31\.d}, pn8, \[x0\]
[^:]+:	a0607c01 	stnt1d	{z0\.d-z1\.d}, pn15, \[x0\]
[^:]+:	a06063c1 	stnt1d	{z0\.d-z1\.d}, pn8, \[x30\]
[^:]+:	a06063e1 	stnt1d	{z0\.d-z1\.d}, pn8, \[sp\]
[^:]+:	a0686001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, #-16, mul vl\]
[^:]+:	a0676001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, #14, mul vl\]
[^:]+:	a06b756d 	stnt1d	{z12\.d-z13\.d}, pn13, \[x11, #-10, mul vl\]
[^:]+:	a060e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0\]
[^:]+:	a060e01d 	stnt1d	{z28\.d-z31\.d}, pn8, \[x0\]
[^:]+:	a060fc01 	stnt1d	{z0\.d-z3\.d}, pn15, \[x0\]
[^:]+:	a060e3c1 	stnt1d	{z0\.d-z3\.d}, pn8, \[x30\]
[^:]+:	a060e3e1 	stnt1d	{z0\.d-z3\.d}, pn8, \[sp\]
[^:]+:	a068e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, #-32, mul vl\]
[^:]+:	a067e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, #28, mul vl\]
[^:]+:	a065ee29 	stnt1d	{z8\.d-z11\.d}, pn11, \[x17, #20, mul vl\]
[^:]+:	a0216001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0216001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0216001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021601f 	stnt1d	{z30\.d-z31\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a0217c01 	stnt1d	{z0\.d-z1\.d}, pn15, \[x0, x1, lsl #3\]
[^:]+:	a02163c1 	stnt1d	{z0\.d-z1\.d}, pn8, \[x30, x1, lsl #3\]
[^:]+:	a02163e1 	stnt1d	{z0\.d-z1\.d}, pn8, \[sp, x1, lsl #3\]
[^:]+:	a03e6001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, x30, lsl #3\]
[^:]+:	a03f6001 	stnt1d	{z0\.d-z1\.d}, pn8, \[x0, xzr, lsl #3\]
[^:]+:	a023674f 	stnt1d	{z14\.d-z15\.d}, pn9, \[x26, x3, lsl #3\]
[^:]+:	a021e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021e01d 	stnt1d	{z28\.d-z31\.d}, pn8, \[x0, x1, lsl #3\]
[^:]+:	a021fc01 	stnt1d	{z0\.d-z3\.d}, pn15, \[x0, x1, lsl #3\]
[^:]+:	a021e3c1 	stnt1d	{z0\.d-z3\.d}, pn8, \[x30, x1, lsl #3\]
[^:]+:	a021e3e1 	stnt1d	{z0\.d-z3\.d}, pn8, \[sp, x1, lsl #3\]
[^:]+:	a03ee001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, x30, lsl #3\]
[^:]+:	a03fe001 	stnt1d	{z0\.d-z3\.d}, pn8, \[x0, xzr, lsl #3\]
[^:]+:	a021ef69 	stnt1d	{z8\.d-z11\.d}, pn11, \[x27, x1, lsl #3\]
