/^Trace/ { n = split($0, parts, "/"); if (n >= 2) print parts[2] }
