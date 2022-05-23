/*

  All operations example for LibBPF. Made by khhs.
  This is a CPP example, but the same principles apply to C aswell!

*/


// We need to define BPF_IMPLEMENT if we want to implement BPF on load
#define BPF_IMPLEMENT
#include "../bpf.h"
#include <fstream>

#include <iostream>
#include <string>
#include <streambuf>

using std::ofstream;
using std::ifstream;
using std::cout;
using std::endl;


void print_file(bpf_file_t file){
    printf("VALID: %s\n", (bpf_verify_file(file) == BPF_TRUE ? "TRUE" : "FALSE"));
    printf("bpf_file_header: %s\n", file.header.bpf_file_header);
    printf("bpf_file_version: %i\n", file.header.bpf_file_version);
    printf("checksum: %i\n", file.header.checksum);
    printf("file_blocks: %i\n", file.header.file_blocks);
    printf("data_size: %i\n", file.header.data_size);
    for(int i = 0; i < file.header.file_blocks; i++) {
        printf("blocks[%i].file_name_hash: %i\n", i, file.blocks[i].file_name_hash);
        printf("blocks[%i].pointer_location: %i\n", i, file.blocks[i].pointer_location);
        printf("blocks[%i].pointer_size: %i\n", i, file.blocks[i].pointer_size);
    }
}

int main(){
    char* names[] = { "test", "test2" }; // Some file names for usage in the lib
    unsigned int sizes[] = { 3, 4 };     // The sizes of the 2 resources data
    unsigned char file_a[] = "HI";       // Resource A
    unsigned char file_b[] = "YO!";      // Resouce B
    unsigned char* data[] = { file_a , file_b }; // The complete data array
    bpf_file_t file = bpf_generate_file(names, 2, sizes, data); // Generate the arrat

    print_file(file);  // Print the file data
  
    /// SERIALIZE AND SAVE A FILE ///

    std::cout << "Saving...\n";

    bpf_file_data_t filedata = bpf_serialize_file(file); // Serialize into a byte[];

    // Write byte array to file
    ofstream stream;
    stream.open("test.bpf");
    if( !stream )
        cout << "Opening file failed" << endl;
    // use operator<< for clarity
    stream.write(filedata.data, filedata.size); // Filedata has the data segment and the size segment.
    // test if write was succesful - not *really* necessary
    if( !stream )
        cout << "Write failed!" << endl;
    
    /// DESERIALIZE FILE ///
  
    bpf_file_t file_deserialized = bpf_deserialize_memory(filedata.data); // Deserialize the file
    print_file(file_deserialized); // Print out the data
    bpf_file_data_t fetched = bpf_read(file_deserialized, "test"); // Fetch the "test" resource from the file
    printf("Fetched: %s\n", fetched.data); //Print out the fetched version

    return 0;
}
