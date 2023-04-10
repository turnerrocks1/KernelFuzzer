//
//  main.c
//  turnerrhackzfuzzer
//
//  Created by Booty Warrior on 8/3/22.
//

#include <stdint.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <IOKit/IOKitLib.h>
#include <sys/types.h>
#include <dirent.h>


void listFiles(const char *path);

int maybe(void){
  static int seeded = 0;
  if(!seeded){
    srand(time(NULL));
    seeded = 1;
  }
  return !(rand() % 100);
}

void flip_bit(void* buf, size_t len){
  if (!len)
    return;
  size_t offset = rand() % len;
  ((uint8_t*)buf)[offset] ^= (0x01 << (rand() % 8));
}

kern_return_t
fake_IOConnectCallMethod(
  mach_port_t connection,
  uint32_t    selector,
  uint64_t   *input,
  uint32_t    inputCnt,
  void       *inputStruct,
  size_t      inputStructCnt,
  uint64_t   *output,
  uint32_t   *outputCnt,
  void       *outputStruct,
  size_t     *outputStructCntP)
{
    kern_return_t new;
    int watcher = 0x0;
    int failortimeout = 0x0;
    int looplimit = 0x100000; //2147483647; lets set the limit to something less time consuming like 100000?
  /*if (maybe()){
    flip_bit(input, sizeof(*input) * inputCnt);
  }*/

  /*if (maybe()){
    flip_bit(inputStruct, inputStructCnt);
  }*/
    
for (;;) { //run the fuzzer in an endless loop cycle :)
    watcher++;
    if (watcher == looplimit) {
        break;
    }
    if(failortimeout == 0x10) {
        break;
    }
    //printf("here : %d", watcher);
    
    new = IOConnectCallMethod(
    connection,
    selector,
    input,
    inputCnt,
    inputStruct,
    inputStructCnt,
    output,
    outputCnt,
    outputStruct,
    outputStructCntP);
    if(new != KERN_SUCCESS) {
        failortimeout++;
    }
    struct arg_struct
    {
        mach_port_t connection;
        uint32_t    selector;
        uint64_t   *input;
        uint32_t    inputCnt;
        void       *inputStruct;
        size_t      inputStructCnt;
        uint64_t   *output;
        uint32_t   *outputCnt;
        void       *outputStruct;
        size_t     *outputStructCntP;
    } args;
    //raceconditiontemplate(<#int func#>, <#uint32_t selection#>)
    pthread_t t;
    //pthread_create(&t, NULL, (void *(*)(void *)) race, (void*) (uint32_t)queueID);
    args.connection = connection;
    args.selector = selector;
    args.input = input;
    args.inputCnt = inputCnt;
    args.inputStruct = inputStruct;
    args.inputStructCnt = inputStructCnt;
    args.output = output;
    args.outputCnt = outputCnt;
    args.outputStruct = outputStruct;
    args.outputStructCntP = outputStructCntP;
    pid_t child_pid = fork();
    if (child_pid == -1) {
        printf("fork failed\n");
        return 0;
    }
    if (child_pid) {
        IOConnectCallMethod(
        connection,
        selector,
        input,
        inputCnt,
        inputStruct,
        inputStructCnt,
        output,
        outputCnt,
        outputStruct,
        outputStructCntP);
    }
    pthread_create(&t, NULL, (void*(*)(void *))IOConnectCallMethod, (void*)&args);
    pthread_join(t, NULL);
    //lets call this first with original parameters ...
    flip_bit(input, sizeof(input));
    flip_bit(inputStruct, sizeof(inputStruct));
    
}
    
    return IOConnectCallMethod(
    connection,
    selector,
    input,
    inputCnt,
    inputStruct,
    inputStructCnt,
    output,
    outputCnt,
    outputStruct,
    outputStructCntP);
    
}

void fuzzXD(io_name_t class, uint32_t num) {
    //lets declare some interesting int's shall we ;)
    printf("about to fuzz %s\n", class);
    unsigned long long interesting[10];
    interesting[1] = INT_MIN;
    interesting[2] = INT_MAX;
    interesting[3] = UINT_MAX;
    interesting[4] = LLONG_MIN;
    interesting[5] = LONG_MAX;
    interesting[6] = ULLONG_MAX;
    interesting[7] = USHRT_MAX;
    interesting[8] = NULL;
    interesting[9] = 0xff;
    
    kern_return_t kr;
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_connect_t connect = MACH_PORT_NULL;
    kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(class), &iterator);
    io_service_t service = IOIteratorNext(iterator);
    kr = IOServiceOpen(service, mach_task_self(), num, &connect);
    //fuzzying like this will probably reach use after frees, type confusions, and BoFs, and oobs
    //but I don't think it hit race condition sceneraios so let's add that feature after a call to
    //the fake IOConnectCallMethod!
    for (uint32_t sel = 0; sel < 30; sel++){
    for (int inter = 0; inter < 10; inter++){
    //When reversing IOKit drivers on iOS ive never seen a method selector past at most 18;
    //I don't know how much more it is for macOS kexts so let's try a wild guess of 30 ;)
    //also flip bit is going to flip input  and inputStruct so might as well squeeze as much as possible
    //;)
    uint64_t inputScalar[0x2000];
    uint32_t inputScalarCnt = interesting[inter];;

    inputScalar[0] = interesting[inter];
    //inputScalar[1] = 0;
    
    char inputStruct[0x2000];
    size_t inputStructCnt = interesting[inter];;

    uint64_t outputScalar[0x2000];
    //outputScalar[1] = interesting[inter];
    uint32_t outputScalarCnt = interesting[inter];

    char outputStruct[0x2000];
    //outputStruct[0] = (char)interesting[inter];
    size_t outputStructCnt = interesting[inter];
    memset(inputStruct,0,sizeof(inputStruct));
    memset(outputStruct,0,sizeof(outputStruct));
    kern_return_t err = fake_IOConnectCallMethod(connect, sel, inputScalar, inputScalarCnt, inputStruct, inputStructCnt, outputScalar, &outputScalarCnt, outputStruct, &outputStructCnt);
        if(err != KERN_SUCCESS) {
            printf("fuzzying class %s failed :(\n",class);
        }
        printf("done fuzzying and flipping %s connectcallmethod bits\n",class);
    }
    }
    
}
int pickkexts(void) {
        kern_return_t kr;
        io_iterator_t iterator = IO_OBJECT_NULL;
    kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOService"), &iterator);
        uint32_t type;
        for (;;) {
            io_service_t service = IOIteratorNext(iterator);
            if (service == IO_OBJECT_NULL) {
                break;
            }
            io_name_t class_name = {};
            IOObjectGetClass(service, class_name);
            uint64_t entry_id = 0;
            IORegistryEntryGetRegistryEntryID(service, &entry_id);
            //printf("%s 0x%llx  ", class_name, entry_id);
            
            io_connect_t connect = MACH_PORT_NULL;
            for (type = 0; type < 0x200; type++) {
                kr = IOServiceOpen(service, mach_task_self(), type, &connect);
                if (kr == KERN_SUCCESS) {
                    goto can_open;
                }
            }
            for (type = 0xffffff00; type != 0; type++) {
                kr = IOServiceOpen(service, mach_task_self(), type, &connect);
                if (kr == KERN_SUCCESS) {
                    goto can_open;
                }
            }
            uint32_t types[] = { 0x61736864, 0x484944, 0x99000002, 0xFF000001, 0x64506950, 0x6C506950, 0x88994242, 0x48494446, 0x48494444, 0x57694669 };
            uint32_t count = sizeof(types); // sizeof(types[0]);
            for (uint32_t type_idx = 0; type_idx < count; type_idx++) {
                type = types[type_idx];
                kr = IOServiceOpen(service, mach_task_self(), type, &connect);
                if (kr == KERN_SUCCESS) {
                    goto can_open;
                }
            }
            //printf("\n");
            goto next;
            //break;
        can_open:
            //return 2;
            fuzzXD(class_name,type);
            //printf("Can open %s with type %d\n",class_name,type);
        next:;
        }
    return 0;
}

/*char* listed[100000] = {''};
void listFiles(const char *path)
{
    int increment = 0;
    struct dirent *dp;
    DIR *dir = opendir(path);

    // Unable to open directory stream
    if (!dir)
        return;

    while ((dp = readdir(dir)) != NULL)
    {
        ++increment;
        //printf("%s\n", dp->d_name);
        listed[increment] = (char)dp->d_name;
        //return (void)listed;
        //((char)dp->d_name + "\n");
    }

    // Close directory stream
    closedir(dir);
}

void getextensionslist() {
    char* extensionpath = "/System/Library/Extensions";
    listFiles(extensionpath);
    
}*/
//I was told not to go about listing every extension from /System/Library/Extensions and just use
//Bazad's IOService iterator Method.

int main(int argc, const char * argv[]) {
    printf("this is a multi-platform IOKit Fuzzer developed by turnerhackz1 on 0x8/0x3/0x2022 XD\n");
    
    /*kern_return_t ret = fake_IOConnectCallMethod(<#mach_port_t connection#>, <#uint32_t selector#>, <#uint64_t *input#>, <#uint32_t inputCnt#>, <#void *inputStruct#>, <#size_t inputStructCnt#>, <#uint64_t *output#>, <#uint32_t *outputCnt#>, <#void *outputStruct#>, <#size_t *outputStructCntP#>)*/
    //getextensionslist();
    int ret = pickkexts();
    //printf("%s listed : ", (char*)listed);
    
    return ret;
}
//main();
