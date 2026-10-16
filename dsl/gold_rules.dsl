rule "all_pillars_pass" {
  when all gates == PASS
  then release = ALLOW
  else release = DENY
}
