# name: attributes for -march=armv8-r
# source: blank.s
# as: -march=armv8-r
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi*

Attribute Section: aeabi
File Attributes
  Tag_CPU_name: "8-R"
  Tag_CPU_arch: v8-R
  Tag_CPU_arch_profile: Realtime
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-2
  Tag_MPextension_use: Allowed
  Tag_Virtualization_use: TrustZone and Virtualization Extensions
