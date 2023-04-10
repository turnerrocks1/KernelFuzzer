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
#include <sys/stat.h>
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

void racetemp(struct arg_struct args) {
    IOConnectCallMethod(args.connection, args.selector, args.input, args.inputCnt, args.inputStruct, args.inputStructCnt, args.output, args.outputCnt, args.outputStruct, args.outputStructCntP);
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
  size_t     *outputStructCntP,
  FILE        *f)
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
    if (child_pid < -1) {
        printf("fork failed\n");
    }
    if (child_pid >= 0) {
        printf("racing conditionattempt\n");
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
    pthread_create(&t, NULL, (void*(*)(void *))racetemp, (void*)&args);
    int errors = pthread_join(t, NULL);
    //printf("error %d\n",errors);
    if (errors != 0) {
        break;
    }
    //lets call this first with original parameters ...
    fprintf(f,"input bits before flipping #%lld\n",(long long)input);
    fprintf(f,"inputStruct bits before flipping #%llx\n",(uint64_t)inputStruct);
    flip_bit(input, sizeof(input));
    flip_bit(inputStruct, sizeof(inputStruct));
    fprintf(f,"input bits flipped to #%lld\n",(long long)input);
    fprintf(f,"inputStruct bits flipped to #%llx\n",(uint64_t)inputStruct);
    
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

void fuzzXD(io_name_t class, uint32_t num, FILE *f) {
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
    fprintf(f,"kext class name #%s\n",class);
    for (uint32_t sel = 0; sel < 30; sel++){
    fprintf(f,"selector method #%d\n",sel);
    for (int inter = 0; inter < 10; inter++){
    //fprintf(f,"kext class name #%s\n",class);
    //fprintf(f,"kext class name #%s\n",class);
    //fprintf(f,"selector method #%d\n",sel);
    fprintf(f,"interesting inter used #%llu\n",interesting[inter]);
    
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
    kern_return_t err = fake_IOConnectCallMethod(connect, sel, inputScalar, inputScalarCnt, inputStruct, inputStructCnt, outputScalar, &outputScalarCnt, outputStruct, &outputStructCnt , f);
        if(err != KERN_SUCCESS) {
            //printf("fuzzying class %s failed :(\n",class);
        }
    }
    }
    printf("done fuzzying and flipping %s connectcallmethod bits\n",class);
    //close resources
    /*close(fd);
    free(chDirName);
    free(chFileName);
    free(chFullPath);*/
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
        
        /* crashing or getting persistent kernel panics and log with no context is no fun :(
         we need a way of knowing this so my idea is to create a folder called fuzzXD and for each kext "class name" create a file with r/w perms and for each IOConnectCall we note down the args passed to it that way if there is a crash before the fuzzer can finish you can replicate the call :)*/
        char* dir = "fuzzer";
        char* filer = "fuzzed";
        //variable declaration
        int fd = 0;
        char *chDirName = NULL;
        char *chFileName = NULL;
        char *chFullPath = NULL;
        struct stat sfileInfo;
        
        //argument processing
        chDirName = (char *)malloc(sizeof(char));
        chFileName = (char *)malloc(sizeof(char));
        chFullPath = (char *)malloc(sizeof(char));
        chDirName = strcpy(chDirName,dir);
        chFileName = strcpy(chFileName,filer);
        
        //create full path of file
        sprintf(chFullPath,"%s/%s.txt",chDirName,chFileName);
        
        //check directory exists or not
        if(stat(chDirName,&sfileInfo) == -1)
        {
            mkdir(chDirName,0700);
            printf("[INFO] Directory Created: %s\n",chDirName);
        }
        
        //create file inside given directory
        fd = creat(chFullPath,0644);
        //FILE *f;
        //f = fopen(fd, "+a");
        
        if(fd == -1)
        {
            printf("[ERROR] Unable to create file: %s\n",chFullPath);
            free(chDirName);
            free(chFileName);
            free(chFullPath);
            return -10;
        }
        
        printf("[INFO] File Created Successfully : %s\n",chFullPath);
        FILE *f = fopen(chFullPath, "w");
        //printf("\n");
        
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
        
        goto next;
        //break;
    can_open: {
        //return 2;
        if(strcmp(class_name,"IOPMrootDomain") == 0) {
            printf("skipping %s\n",class_name);
            goto next;
        }
        /*close resources
         close(fd);
         free(chDirName);
         free(chFileName);
         free(chFullPath);*/
        fuzzXD(class_name,type,f);
        goto next;
    }
    next:{
        
    };
        
        //close resources
        close(fd);
        free(chDirName);
        free(chFileName);
        free(chFullPath);
        //return 0;
    }
    return 0;
}

//I was told not to go about listing every extension from /System/Library/Extensions and just use
//Bazad's IOService iterator Method.

int main(int argc, const char * argv[]) {
    printf("this is a multi-platform IOKit Fuzzer developed by turnerhackz1 on 0x8/0x3/0x2022 XD\n");
    
    int ret = pickkexts();
    
    return ret;
}

