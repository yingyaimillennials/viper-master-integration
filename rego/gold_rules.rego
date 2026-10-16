package viper.gold

all_gates_pass {
  every g in input.gates { g == "PASS" }
}

all_pillars_pass {
  all_gates_pass
}