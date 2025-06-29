#name: Check linker stubs with indirect calls handle BTI when target has BTI.
#source: bti-far-opt.s
#target: [check_shared_lib_support]
#as: -defsym __property_bti__=1
#ld: -shared -T bti-far.ld
#objdump: -dr

[^:]*: *file format elf64-.*aarch64


Disassembly of section \.plt:

0000000000018000 <\.plt>:
   18000:	d503245f 	bti	c
   18004:	a9bf7bf0 	stp	x16, x30, \[sp, #-16\]!
   18008:	[[:xdigit:]]{8} 	adrp	x16, [[:xdigit:]]+ <_GLOBAL_OFFSET_TABLE_>
   1800c:	f9400e11 	ldr	x17, \[x16, #24\]
   18010:	91006210 	add	x16, x16, #0x18
   18014:	d61f0220 	br	x17
   18018:	d503201f 	nop
   1801c:	d503201f 	nop

0000000000018020 <foo@plt>:
   18020:	[[:xdigit:]]{8} 	adrp	x16, [[:xdigit:]]+ <_GLOBAL_OFFSET_TABLE_>
   18024:	f9401211 	ldr	x17, \[x16, #32\]
   18028:	91008210 	add	x16, x16, #0x20
   1802c:	d61f0220 	br	x17
   18030:	14000004 	b	18040 <__foo_bti_veneer\+0x8>
   18034:	d503201f 	nop

0000000000018038 <__foo_bti_veneer>:
   18038:	d503245f 	bti	c
   1803c:	17fffff9 	b	18020 <foo@plt>

Disassembly of section \.text:

0000000000020000 <_start>:
   20000:	97ffe008 	bl	18020 <foo@plt>
   20004:	9400000d 	bl	20038 <___veneer>
   20008:	94000001 	bl	2000c <baz>

000000000002000c <baz>:
   2000c:	d503201f 	nop

0000000000020010 <baz_bti_>:
   20010:	d503241f 	bti

0000000000020014 <baz_bti_c>:
   20014:	d503245f 	bti	c

0000000000020018 <baz_bti_j>:
   20018:	d503249f 	bti	j

000000000002001c <baz_bti_jc>:
   2001c:	d50324df 	bti	jc

0000000000020020 <baz_paciasp>:
   20020:	d503233f 	paciasp

0000000000020024 <baz_pacibsp>:
   20024:	d503237f 	pacibsp
   20028:	1400000c 	b	20058 <___bti_veneer\+0x8>
   2002c:	d503201f 	nop

0000000000020030 <___bti_veneer>:
   20030:	d503245f 	bti	c
   20034:	17fffff6 	b	2000c <baz>

0000000000020038 <___veneer>:
   20038:	90091910 	adrp	x16, 12340000 <foo>
   2003c:	9102a210 	add	x16, x16, #0xa8
   20040:	d61f0200 	br	x16
	\.\.\.

0000000000020050 <___bti_veneer>:
   20050:	d503245f 	bti	c
   20054:	17ffffef 	b	20010 <baz_bti_>

Disassembly of section \.far:

0000000012340000 <foo>:
    12340000:	94000032 	bl	123400c8 <___veneer>
    12340004:	9400001d 	bl	12340078 <___veneer>
    12340008:	94000022 	bl	12340090 <___veneer>
    1234000c:	94000035 	bl	123400e0 <___veneer>
    12340010:	9400003a 	bl	123400f8 <___veneer>
    12340014:	94000013 	bl	12340060 <___veneer>
    12340018:	94000026 	bl	123400b0 <___veneer>

000000001234001c <bar>:
    1234001c:	1400000b 	b	12340048 <__foo_veneer>
    12340020:	1400002a 	b	123400c8 <___veneer>
    12340024:	14000015 	b	12340078 <___veneer>
    12340028:	1400001a 	b	12340090 <___veneer>
    1234002c:	1400002d 	b	123400e0 <___veneer>
    12340030:	14000032 	b	123400f8 <___veneer>
    12340034:	1400000b 	b	12340060 <___veneer>
    12340038:	1400001e 	b	123400b0 <___veneer>
    1234003c:	00000000 	udf	#0
    12340040:	14000034 	b	12340110 <___veneer\+0x18>
    12340044:	d503201f 	nop

0000000012340048 <__foo_veneer>:
    12340048:	90f6e6d0 	adrp	x16, 18000 <.plt>
    1234004c:	9100e210 	add	x16, x16, #0x38
    12340050:	d61f0200 	br	x16
	\.\.\.

0000000012340060 <___veneer>:
    12340060:	90f6e710 	adrp	x16, 20000 <_start>
    12340064:	91008210 	add	x16, x16, #0x20
    12340068:	d61f0200 	br	x16
	\.\.\.

0000000012340078 <___veneer>:
    12340078:	90f6e710 	adrp	x16, 20000 <_start>
    1234007c:	91014210 	add	x16, x16, #0x50
    12340080:	d61f0200 	br	x16
	\.\.\.

0000000012340090 <___veneer>:
    12340090:	90f6e710 	adrp	x16, 20000 <_start>
    12340094:	91005210 	add	x16, x16, #0x14
    12340098:	d61f0200 	br	x16
	\.\.\.

00000000123400a8 <___bti_veneer>:
    123400a8:	d503245f 	bti	c
    123400ac:	17ffffdc 	b	1234001c <bar>

00000000123400b0 <___veneer>:
    123400b0:	90f6e710 	adrp	x16, 20000 <_start>
    123400b4:	91009210 	add	x16, x16, #0x24
    123400b8:	d61f0200 	br	x16
	\.\.\.

00000000123400c8 <___veneer>:
    123400c8:	90f6e710 	adrp	x16, 20000 <_start>
    123400cc:	9100c210 	add	x16, x16, #0x30
    123400d0:	d61f0200 	br	x16
	\.\.\.

00000000123400e0 <___veneer>:
    123400e0:	90f6e710 	adrp	x16, 20000 <_start>
    123400e4:	91006210 	add	x16, x16, #0x18
    123400e8:	d61f0200 	br	x16
	\.\.\.

00000000123400f8 <___veneer>:
    123400f8:	90f6e710 	adrp	x16, 20000 <_start>
    123400fc:	91007210 	add	x16, x16, #0x1c
    12340100:	d61f0200 	br	x16
	\.\.\.
