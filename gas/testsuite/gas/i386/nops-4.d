#source: nops-4.s
#objdump: -drw
#name: i386 nops 4

.*: +file format .*

Disassembly of section .text:

0+ <nop31>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 1d                	jmp    20 <nop30>
[ 	]*[a-f0-9]+:	2e 8d 74 26 00       	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+20 <nop30>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 1c                	jmp    40 <nop29>
[ 	]*[a-f0-9]+:	8d 74 26 00          	lea    (0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+40 <nop29>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 1b                	jmp    60 <nop28>
[ 	]*[a-f0-9]+:	8d 76 00             	lea    (0x)?0\(%esi\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+60 <nop28>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 1a                	jmp    80 <nop27>
[ 	]*[a-f0-9]+:	66 90                	xchg   %ax,%ax
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+80 <nop27>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 19                	jmp    a0 <nop26>
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+a0 <nop26>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 18                	jmp    c0 <nop25>
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+c0 <nop25>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 17                	jmp    e0 <nop24>
[ 	]*[a-f0-9]+:	8d b4 26 00 00 00 00 	lea    (0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+e0 <nop24>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	eb 16                	jmp    100 <nop23>
[ 	]*[a-f0-9]+:	8d b6 00 00 00 00    	lea    (0x)?0\(%esi\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+100 <nop23>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	8d b4 26 00 00 00 00 	lea    (0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+120 <nop22>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	8d b6 00 00 00 00    	lea    (0x)?0\(%esi\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+140 <nop21>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	2e 8d 74 26 00       	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+160 <nop20>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	8d 74 26 00          	lea    (0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+180 <nop19>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	8d 76 00             	lea    (0x)?0\(%esi\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+1a0 <nop18>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	66 90                	xchg   %ax,%ax
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+1c0 <nop17>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi

0+1e0 <nop16>:
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	f8                   	clc
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
[ 	]*[a-f0-9]+:	2e 8d b4 26 00 00 00 00 	lea    %cs:(0x)?0\(%esi,%eiz,1\),%esi
#pass
