[ ! -d "build" ] && mkdir build
cd build
echo "Generating file"
echo '#define BPF_IMPLEMENT' | cat - ../bpf.h > bpf.c
echo "Building .o file"
g++ -c bpf.c
gcc -shared -o libbpf.so bpf.o
