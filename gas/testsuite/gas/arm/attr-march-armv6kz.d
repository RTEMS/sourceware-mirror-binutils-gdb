# name: attributes for -march=armv6kz
# source: blank.s
# as: -march=armv6kz
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi*

Attribute Section: aeabi
File Attributes
  Tag_CPU_name: "6KZ"
  Tag_CPU_arch: v6KZ
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-1
  Tag_Virtualization_use: TrustZone
