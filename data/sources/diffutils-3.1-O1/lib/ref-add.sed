/^# Packages using this file: / {
  s/# Packages using this file://
  ta
  :a
  s/ diffutils / diffutils /
  tb
  s/ $/ diffutils /
  :b
  s/^/# Packages using this file:/
}
