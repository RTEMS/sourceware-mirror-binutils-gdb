# name: attributes for architecture extension vfpv3-fp16
# source: blank.s
# as: -march=armv7ve+vfpv3-fp16
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi*

Attribute Section: aeabi
File Attributes
  Tag_CPU_name: "7VE"
  Tag_CPU_arch: v7
  Tag_CPU_arch_profile: Application
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-2
  Tag_FP_arch: VFPv3
  Tag_FP_HP_extension: Allowed
  Tag_MPextension_use: Allowed
  Tag_DIV_use: Allowed in v7-A with integer division extension
  Tag_Virtualization_use: TrustZone and Virtualization Extensions

