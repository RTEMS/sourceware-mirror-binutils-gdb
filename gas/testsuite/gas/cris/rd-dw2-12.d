#readelf: -wl
#source: pushpop.s
#as: --emulation=criself --gdwarf2

# Pushes and other prefixes.
#...
 Line Number Statements:
  \[0x.*\]  Extended opcode 2: set Address to (0x)?0
  \[0x.*\]  Special opcode .*: advance Address by 0 to (0x)?0 and Line by 4 to 5
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x4 and Line by 1 to 6
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x8 and Line by 1 to 7
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xc and Line by 2 to 9
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x10 and Line by 1 to 10
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x14 and Line by 1 to 11
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x18 and Line by 2 to 13
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x1c and Line by 1 to 14
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x20 and Line by 1 to 15
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x24 and Line by 2 to 17
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x28 and Line by 1 to 18
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x2c and Line by 2 to 20
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x30 and Line by 1 to 21
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x34 and Line by 1 to 22
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x38 and Line by 2 to 24
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x3c and Line by 1 to 25
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x40 and Line by 2 to 27
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x44 and Line by 1 to 28
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x48 and Line by 2 to 30
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x4c and Line by 1 to 31
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x50 and Line by 1 to 32
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x54 and Line by 2 to 34
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x58 and Line by 1 to 35
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x5c and Line by 1 to 36
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x60 and Line by 2 to 38
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x64 and Line by 1 to 39
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x68 and Line by 1 to 40
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x6c and Line by 2 to 42
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x70 and Line by 1 to 43
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x74 and Line by 1 to 44
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x78 and Line by 2 to 46
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x7c and Line by 1 to 47
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x80 and Line by 1 to 48
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x84 and Line by 2 to 50
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x88 and Line by 1 to 51
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x8c and Line by 1 to 52
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x90 and Line by 2 to 54
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x94 and Line by 1 to 55
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x98 and Line by 1 to 56
  \[0x.*\]  Advance Line by 9 to 65
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x9c and Line by 0 to 65
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xa0 and Line by 1 to 66
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xa4 and Line by 1 to 67
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xa8 and Line by 2 to 69
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xac and Line by 1 to 70
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xb0 and Line by 1 to 71
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xb4 and Line by 2 to 73
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xb8 and Line by 1 to 74
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xbc and Line by 1 to 75
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xc0 and Line by 2 to 77
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xc4 and Line by 1 to 78
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xc8 and Line by 1 to 79
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xcc and Line by 2 to 81
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xd0 and Line by 1 to 82
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xd4 and Line by 1 to 83
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xd8 and Line by 2 to 85
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xdc and Line by 1 to 86
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xe0 and Line by 1 to 87
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xe4 and Line by 2 to 89
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xe8 and Line by 1 to 90
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xec and Line by 1 to 91
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xf0 and Line by 2 to 93
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xf4 and Line by 1 to 94
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xf8 and Line by 1 to 95
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0xfc and Line by 2 to 97
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x100 and Line by 1 to 98
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x104 and Line by 1 to 99
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x108 and Line by 2 to 101
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x10c and Line by 1 to 102
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x110 and Line by 1 to 103
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x114 and Line by 2 to 105
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x118 and Line by 1 to 106
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x11c and Line by 1 to 107
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x120 and Line by 2 to 109
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x124 and Line by 1 to 110
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x128 and Line by 1 to 111
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x12c and Line by 2 to 113
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x130 and Line by 1 to 114
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x134 and Line by 1 to 115
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x138 and Line by 2 to 117
  \[0x.*\]  Special opcode .*: advance Address by 4 to 0x13c and Line by 1 to 118
  \[0x.*\]  Special opcode .*: advance Address by 2 to 0x13e and Line by 1 to 119
  \[0x.*\]  Special opcode .*: advance Address by 2 to 0x140 and Line by 1 to 120
  \[0x.*\]  Advance PC by 4 to 0x144
  \[0x.*\]  Extended opcode 1: End of Sequence
