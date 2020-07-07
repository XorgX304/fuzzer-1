# fuzzer
Ptrace fuzzer experiments based on https://h0mbre.github.io/Fuzzing-Like-A-Caveman-4/#

- Modified it to snapshot also Heap (needed for a more real target than dummy one)
- Fixed small bug with percentage showing of Coverage
- debuged, debuged, debuged till it work with real target (Oniguruma library :))

TODO:
- automatic snapshot collection from /proc/maps
- shared memory for Corpus
- Mutators

Fuzzing at ca. 60k exec/s. I can imagine you can scale it even more with 25% drop per total cores. With 4 cores I achieved 60k exec/s (25% total drop, since 1 core was ca 20k). Below you can also see how I trigger Stack Protector with my crash. #fuzzing #speed Fuzzing older "Oniguruma" regular expression library


![Fuzzer](dragonfly-60k_sec.png)
