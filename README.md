# LibBPF
A very basic single-header C/C++ library for packing resources into a single file.  
The library is not the most optimized but it is works for it's purpose.

## Usage
The library is easily used, with a couple of examples(and more to be added), and it is very powerful.  
A basic loading script could be built as such:
```c
bpf_file_t file_deserialized = bpf_deserialize_memory(filedata); // Load file from memory. File loading is not supported yet.
bpf_file_data_t fetched = bpf_read(file_deserialized, "test");   // Load the data of resource called "test" from bpf_read.
char* data = fetched.data; // Fetch the data
unsigned int size = fetched.size; // Fetch the size of the data
```
This isnt the best explanation in the world, but i hope it helps. There is also code for making and serializing files.  

If you want better explanations, just create an issue asking for help, or join our [discord](https://discord.gg/wGuAHmyzBh)(the openability discord)!  
There are also examples if needed of course just check the `examples` folder!
