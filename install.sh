./build.sh
cd build
cp ../bpf.h /usr/include/bpf.h
printf "Installed header! Do you want a linkable library version for it aswell(y/n)?"
read answer
if [ "$answer" != "${answer#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
    cp libbpf.so /usr/local/lib/libbpf.so
fi

echo "Installed LibBPF to your system!"
