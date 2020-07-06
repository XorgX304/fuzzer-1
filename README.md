# fuzzer
Ptrace fuzzer experiments

Fuzzing at ca. 60k exec/s. I can imagine you can scale it even more with 25% drop per total cores. With 4 cores I achieved 60k exec/s (25% total drop, since 1 core was ca 20k). Below you can also see how I trigger Stack Protector with my crash. #fuzzing #speed Fuzzing older "Oniguruma" regular expression library


![Fuzzer](dragonfly-60k_sec.png)
