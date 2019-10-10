//
//  appmon.m
//  appmon
//
//  Created by Patrick Wardle.
// Modified by Chris Ross
// Majority of the code in appmon.h and appmon.m was taken from the ProcessMonitor project by Patrick Wardle
// https://github.com/objective-see/ProcessMonitor
// License: https://github.com/objective-see/ProcessMonitor/blob/master/LICENSE.md

#import "appmon.h"
#import <libproc.h>
#import <bsm/libbsm.h>
#import <sys/sysctl.h>
#include <signal.h>

EventHandlerFn handler;

//endpoint
es_client_t* endpointClient = nil;

es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_KEXTLOAD, ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETEXTATTR};

//helper functions

// Convert the event type to a string
NSString* event_type_str(const es_event_type_t event_type) {
    switch(event_type) {
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: return @"ES_EVENT_TYPE_NOTIFY_GET_TASK";
        case ES_EVENT_TYPE_NOTIFY_MMAP: return @"ES_EVENT_TYPE_NOTIFY_MMAP";
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: return @"ES_EVENT_TYPE_NOTIFY_MPROTECT";
        case ES_EVENT_TYPE_NOTIFY_EXEC: return @"ES_EVENT_NOTIFY_EXEC";
        case ES_EVENT_TYPE_NOTIFY_FORK: return @"ES_EVENT_NOTIFY_FORK";
        case ES_EVENT_TYPE_NOTIFY_EXIT: return @"ES_EVENT_NOTIFY_EXIT";
        case ES_EVENT_TYPE_NOTIFY_CREATE: return @"ES_EVENT_TYPE_NOTIFY_CREATE";
        case ES_EVENT_TYPE_NOTIFY_CLOSE: return @"ES_EVENT_TYPE_NOTIFY_CLOSE";
        case ES_EVENT_TYPE_NOTIFY_WRITE: return @"ES_EVENT_TYPE_NOTIFY_WRITE";
        case ES_EVENT_TYPE_NOTIFY_RENAME: return @"ES_EVENT_TYPE_NOTIFY_RENAME";
        case ES_EVENT_TYPE_NOTIFY_OPEN: return @"ES_EVENT_TYPE_NOTIFY_OPEN";
        case ES_EVENT_TYPE_NOTIFY_UNLINK: return @"ES_EVENT_TYPE_NOTIFY_UNLINK";
        case ES_EVENT_TYPE_NOTIFY_LINK: return @"ES_EVENT_TYPE_NOTIFY_LINK";
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: return @"ES_EVENT_TYPE_NOTIFY_KEXTLOAD";
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: return @"ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD";
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: return @"ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN";
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return @"ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA";
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE: return @"ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN";
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE: return @"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE";
        case ES_EVENT_TYPE_NOTIFY_SIGNAL: return @"ES_EVENT_TYPE_NOTIFY_SIGNAL";
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST: return @"ES_EVENT_TYPE_NOTIFY_SETATTRLIST";
        case ES_EVENT_TYPE_NOTIFY_SETOWNER: return @"ES_EVENT_TYPE_NOTIFY_SETOWNER";
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: return @"ES_EVENT_TYPE_NOTIFY_SETEXTATTR";
        default: return @"EVENT_TYPE_UNKNOWN";
    }
}

//convert es_string_token_t to string
NSString* convertStringToken(es_string_token_t* stringToken)
{
    //string
    NSString* string = nil;
    
    //sanity check(s)
    if( (NULL == stringToken) ||
        (NULL == stringToken->data) ||
        (stringToken->length <= 0) )
    {
        //bail
        goto bail;
    }
        
    //convert to data, then to string
    string = [NSString stringWithUTF8String:[[NSData dataWithBytes:stringToken->data length:stringToken->length] bytes]];
    
bail:
    
    return string;
    
}

// get parent of arbitrary process
pid_t getParentID(pid_t child)
{
    //parent id
    pid_t parentID = -1;
    
    //kinfo_proc struct
    struct kinfo_proc processStruct = {0};
    
    //size
    size_t procBufferSize = 0;
    
    //mib
    const u_int mibLength = 4;
    
    //syscall result
    int sysctlResult = -1;
    
    //init buffer length
    procBufferSize = sizeof(processStruct);
    
    //init mib
    int mib[mibLength] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, child};
    
    //make syscall
    sysctlResult = sysctl(mib, mibLength, &processStruct, &procBufferSize, NULL, 0);
    
    //check if got ppid
    if( (noErr == sysctlResult) &&
        (0 != procBufferSize) )
    {
        //save ppid
        parentID = processStruct.kp_eproc.e_ppid;
    }
    
    return parentID;
}


@implementation Inspecter : NSObject
// Monitoring
-(BOOL)start:(EventCallbackBlock)callback
{
    BOOL started = NO;
     //result
    es_new_client_result_t result = 0;
    
    @synchronized (self)
    {
        result = es_new_client(&endpointClient, ^(es_client_t *client, const es_message_t *message){
            SecurityEvent *newEvent = nil;
            newEvent = [[SecurityEvent alloc] init:(es_message_t *_Nonnull)message];
            
            if (nil != newEvent) {
                callback(newEvent);
            }
        });
        
        
        //error?
        if(ES_NEW_CLIENT_RESULT_SUCCESS != result)
        {
            //err msg
            NSLog(@"ERROR: es_new_client() failed with %d", result);
            
            //bail
            goto bail;
        }
        
        //clear cache
        
        if(ES_CLEAR_CACHE_RESULT_SUCCESS != es_clear_cache(endpointClient))
        {
            //err msg
            NSLog(@"ERROR: es_clear_cache() failed");
            
            //bail
            goto bail;
        }
        
        //subscribe
        if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, events, sizeof(events)/sizeof(events[0])))
        {
            //err msg
            NSLog(@"ERROR: es_subscribe() failed");
            
            //bail
            goto bail;
        }
    }
    
    started = YES;
    
bail:
    return started;
}

-(BOOL)stop
{
     //flag
    BOOL stopped = NO;
    
    //sync
    @synchronized (self)
    {
        
        //unsubscribe & delete
        if(NULL != endpointClient)
        {
           //unsubscribe
            if(ES_RETURN_SUCCESS != es_unsubscribe_all(endpointClient))
            {
                //err msg
                NSLog(@"ERROR: es_unsubscribe_all() failed");
                
                //bail
                goto bail;
            }
           
           //delete client
            if(ES_RETURN_SUCCESS != es_delete_client(endpointClient))
            {
                //err msg
                NSLog(@"ERROR: es_delete_client() failed");
                
                //bail
                goto bail;
            }
           
           //unset
           endpointClient = NULL;
           
           //happy
           stopped = YES;
        }
        
    } //sync
    
bail:
    
    return stopped;
}

@end

@implementation SecurityEvent

-(id)init:(es_message_t*)message
{
    self = [super init];
    if (nil != self)
    {
        // We don't care about messages for the es_client binary
        if (!message->process->is_es_client) {
            
            self.timestamp = [NSDate date];
            self.hostname = [[NSHost currentHost] name];
            self.metadata = [NSMutableDictionary dictionary];
            self.type = event_type_str(message->event_type);
            
            [self extractOriginProcessDataForEvent:message->process];
            // Handle the event and extract the event details as metadata
            switch (message->event_type) {
                   
                case ES_EVENT_TYPE_NOTIFY_EXEC:
                    // extract the arguments for exec events
                    [self extractArgs:&message->event];
                    [self handleProcessEventData:message->event.exec.target];
                    [self extractEnvironmentVariablesForProcess:&message->event.exec];
                    break;
                case ES_EVENT_TYPE_NOTIFY_FORK:
                    [self handleProcessEventData:message->event.fork.child];
                    break;
                case ES_EVENT_TYPE_NOTIFY_EXIT:
                    [self handleProcessEventData:message->process];
                    break;
                case ES_EVENT_TYPE_NOTIFY_MMAP:
                    [self handleMMapEventData:&message->event.mmap];
                    break;
                case ES_EVENT_TYPE_NOTIFY_MPROTECT:
                    [self handleMProtectEventData:&message->event.mprotect];
                    break;
                case ES_EVENT_TYPE_NOTIFY_GET_TASK:
                    [self handleGetTaskEventData:&message->event.get_task];
                    break;
                case ES_EVENT_TYPE_NOTIFY_CREATE:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_OPEN:
                    [self extractPaths:message];
                    break;
                    
                case ES_EVENT_TYPE_NOTIFY_WRITE:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_CLOSE:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_LINK:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_RENAME:
                    [self extractPaths:message];
                    break;
                    
                case ES_EVENT_TYPE_NOTIFY_UNLINK:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
                    [self handleKextEventData:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
                    [self handleKextEventData:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
                    [self.metadata setValue:convertStringToken(&message->event.iokit_open.user_client_class) forKey:@"user_class"];
                    [self.metadata setValue:[NSNumber numberWithUnsignedInt:message->event.iokit_open.user_client_type] forKey:@"user_client"];
                    break;
                case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
                    [self extractPaths:message];
                    break;
                case ES_EVENT_TYPE_NOTIFY_SIGNAL:
                    [self extractSignalinfo:&message->event.signal];
                    break;
                case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
                    [self handleSetAttrlistEventData:&message->event.setattrlist];
                    break;
                case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
                    [self handleSetExtattrEventData:&message->event.setextattr];
                    break;
                case ES_EVENT_TYPE_NOTIFY_SETOWNER:
                    [self handleSetOwnerEventData:&message->event.setowner];
                    break;
                case ES_EVENT_TYPE_LAST:
                    break; // Don't care
                default:
                    break;
            }
            return self;
        }
        return nil;
    }
    
    
    return nil;
}

-(void)extractEnvironmentVariablesForProcess:(es_event_exec_t *)process
{
    [self.metadata setValue:[NSMutableArray array] forKey:@"env_variables"];
    int count = es_exec_env_count(process);
    
    for (int i = 0; i < count; i++) {
        es_string_token_t env_value = es_exec_env(process, (uint32_t)i);
        [self.metadata[@"env_variables"] addObject:convertStringToken(&env_value)];
    }
}

-(void)handleSetOwnerEventData:(es_event_setowner_t *)owner
{
    [self.metadata setValue:convertStringToken(&owner->target->path) forKey:@"filepath"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:owner->uid] forKey:@"uid"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:owner->gid] forKey:@"gid"];
}

-(void)handleSetExtattrEventData:(es_event_setextattr_t *)extattr
{
    [self.metadata setValue:convertStringToken(&extattr->target->path) forKey:@"filepath"];
    [self.metadata setValue:convertStringToken(&extattr->extattr) forKey:@"extendedattr"];
}

-(void)handleSetAttrlistEventData:(es_event_setattrlist_t *)attr
{
    [self.metadata setValue:convertStringToken(&attr->target->path) forKey:@"filepath"];
    // TODO: parse the setattrlist struct and retrieve the values
}

-(void)handleGetTaskEventData:(es_event_get_task_t *)task
{
    //obtain all the target process info. Just re-use the handleProcessEvent function
    [self handleProcessEventData:task->target];
    
}

-(void)extractSignalinfo:(es_event_signal_t *)sig
{
    switch (sig->sig) {
        case SIGHUP:
            [self.metadata setValue:@"SIGHUP" forKey:@"signal"];
            break;
        case SIGINT:
            [self.metadata setValue:@"SIGINT" forKey:@"signal"];
            break;
        case SIGQUIT:
            [self.metadata setValue:@"SIGQUIT" forKey:@"signal"];
            break;
        case SIGILL:
            [self.metadata setValue:@"SIGILL" forKey:@"signal"];
            break;
        case SIGTRAP:
            [self.metadata setValue:@"SIGTRAP" forKey:@"signal"];
            break;
        case SIGABRT:
            [self.metadata setValue:@"SIGABRT" forKey:@"signal"];
            break;
        case SIGEMT:
            [self.metadata setValue:@"SIGEMT" forKey:@"signal"];
            break;
        case SIGFPE:
            [self.metadata setValue:@"SIGFPE" forKey:@"signal"];
            break;
        case SIGKILL:
            [self.metadata setValue:@"SIGKILL" forKey:@"signal"];
            break;
        case SIGBUS:
            [self.metadata setValue:@"SIGBUS" forKey:@"signal"];
            break;
        case SIGSEGV:
            [self.metadata setValue:@"SIGSEGV" forKey:@"signal"];
            break;
        case SIGSYS:
            [self.metadata setValue:@"SIGSYS" forKey:@"signal"];
            break;
        case SIGPIPE:
            [self.metadata setValue:@"SIGPIPE" forKey:@"signal"];
            break;
        case SIGALRM:
            [self.metadata setValue:@"SIGALRM" forKey:@"signal"];
            break;
        case SIGTERM:
            [self.metadata setValue:@"SIGTERM" forKey:@"signal"];
            break;
        case SIGURG:
            [self.metadata setValue:@"SIGURG" forKey:@"signal"];
            break;
        case SIGSTOP:
            [self.metadata setValue:@"SIGSTOP" forKey:@"signal"];
            break;
        case SIGTSTP:
            [self.metadata setValue:@"SIGTSTP" forKey:@"signal"];
            break;
        case SIGCONT:
            [self.metadata setValue:@"SIGCONT" forKey:@"signal"];
            break;
        case SIGCHLD:
            [self.metadata setValue:@"SIGCHLD" forKey:@"signal"];
            break;
        case SIGTTIN:
            [self.metadata setValue:@"SIGTTIN" forKey:@"signal"];
            break;
        case SIGTTOU:
            [self.metadata setValue:@"SIGTTOU" forKey:@"signal"];
            break;
        case SIGIO:
            [self.metadata setValue:@"SIGIO" forKey:@"signal"];
            break;
        case SIGXCPU:
            [self.metadata setValue:@"SIGXCPU" forKey:@"signal"];
            break;
        case SIGXFSZ:
            [self.metadata setValue:@"SIGXFSZ" forKey:@"signal"];
            break;
        case SIGVTALRM:
            [self.metadata setValue:@"SIGVTALRM" forKey:@"signal"];
            break;
        case SIGPROF:
            [self.metadata setValue:@"SIGPROF" forKey:@"signal"];
            break;
        case SIGWINCH:
            [self.metadata setValue:@"SIGWINCH" forKey:@"signal"];
            break;
        case SIGINFO:
            [self.metadata setValue:@"SIGINFO" forKey:@"signal"];
            break;
        case SIGUSR1:
            [self.metadata setValue:@"SIGUSR1" forKey:@"signal"];
            break;
        case SIGUSR2:
            [self.metadata setValue:@"SIGUSR2" forKey:@"signal"];
            break;
        default:
            break;
    }
    
    [self extractSigningInfo:sig->target forOriginProcess:false];
}

-(void)handleKextEventData:(es_message_t *)kext
{
    NSString *kextID;
    switch (kext->event_type) {
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            kextID = convertStringToken(&kext->event.kextload.identifier);
            break;
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            kextID = convertStringToken(&kext->event.kextunload.identifier);
        default:
            break;
    }
    
    // https://github.com/erikberglund/DiskHandler/blob/4d7473c7a1f86ce4a5474e8374df100c2493a434/DiskHandler/DiskHandler/Bridging/KextManagerBridge.m#L15
    NSURL *url = CFBridgingRelease(KextManagerCreateURLForBundleIdentifier(kCFAllocatorDefault, (__bridge CFStringRef)kextID));
    
    if (url) {
        NSBundle *bundle = [NSBundle bundleWithURL:url];
        [self.metadata setValue:bundle.bundleIdentifier forKey:@"bundleidentifier"];
        [self.metadata setValue:bundle.bundlePath forKey:@"bundlepath"];
        [self.metadata setValue:bundle.executablePath forKey:@"executable"];
        
        // TODO:
    } else {
        // If the path is null
        // TODO: KextManagerCreateURLForBundleIdentifier function supposedly only works for kexts that are located in /System/Library/KernelExtensions/. Need logic to handle third-party kexts
    }
}

-(void)handleMProtectEventData:(es_event_mprotect_t *)mprotect
{
    //obtain the source address for mprotect
    
    [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:mprotect->address] forKey:@"startingaddress"];
    
    // obtain the length of the memory region to be protected
    [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:mprotect->size] forKey:@"size"];
    
    // Obtain the protection flags used for the memory region
    [self.metadata setValue:[NSMutableArray array] forKey:@"mprotectflags"];
    
    if ((PROT_EXEC & mprotect->protection) == PROT_EXEC) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_EXEC"];
    }
    
    if ((PROT_WRITE & mprotect->protection) == PROT_WRITE) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_WRITE"];
    }
    
    if ((PROT_READ & mprotect->protection) == PROT_READ) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_READ"];
    }
    
    if ((PROT_NONE & mprotect->protection) == PROT_NONE) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_NONE"];
    }
    
    
}

-(void)handleMMapEventData:(es_event_mmap_t *)mmap
{
    // obtain properties for the source es_file_t struct
    [self.metadata setValue:convertStringToken(&mmap->source->path) forKey:@"sourcepath"];
    [self.metadata setValue:[NSNumber numberWithBool:mmap->source->path_truncated] forKey:@"path_truncated"];
    
    // obtain some of the other mmap properties
    [self.metadata setValue:[NSNumber numberWithUnsignedLong:mmap->file_pos] forKey:@"fileoffset"];
    
    //Obtain the MMAP flags
    [self.metadata setValue:[NSMutableArray array] forKey:@"mmapflags"];
    
    if ((MAP_SHARED & mmap->flags) == MAP_SHARED) {
        [self.metadata[@"mmapflags"] addObject:@"MAP_SHARED"];
    }
    
    if ((MAP_PRIVATE & mmap->flags) == MAP_PRIVATE) {
        [self.metadata[@"mmapflags"] addObject:@"MAP_PRIVATE"];
    }
    
    if ((MAP_FIXED & mmap->flags) == MAP_FIXED) {
        [self.metadata[@"mmapflags"] addObject:@"MAP_FIXED"];
    }
    
    //Obtain the MMAP protection values
    [self.metadata setValue:[NSMutableArray array] forKey:@"mmapprotection"];
    
    if ((PROT_EXEC & mmap->protection) == PROT_EXEC) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_EXEC"];
    }
    
    if ((PROT_WRITE & mmap->protection) == PROT_WRITE) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_WRITE"];
    }
    
    if ((PROT_READ & mmap->protection) == PROT_READ) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_READ"];
    }
    
    if ((PROT_NONE & mmap->protection) == PROT_NONE) {
        [self.metadata[@"mmapprotection"] addObject:@"PROT_NONE"];
    }
    
    //Grab the max_protect value
    [self.metadata setValue:[NSNumber numberWithInt:mmap->max_protection] forKey:@"max_protection"];
    
    // Grab the uid, filesize, etc from the stat struct
    self.uid = [NSNumber numberWithUnsignedInt:mmap->source->stat.st_uid];
    [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:mmap->source->stat.st_size] forKey:@"size"];
}

// handle process events in general
-(void)handleProcessEventData:(es_process_t *)process
{
    // Populate values for pid for the general event info and for the metadata
    
    [self.metadata setValue:[NSNumber numberWithInt:audit_token_to_pid(process->audit_token)] forKey:@"pid"];
    [self.metadata setValue:[NSNumber numberWithInt:audit_token_to_euid(process->audit_token)] forKey:@"uid"];
    [self.metadata setValue:convertStringToken(&process->executable->path) forKey:@"binarypath"];
    [self.metadata setValue:[NSNumber numberWithInt:process->ppid] forKey:@"ppid"];
    // Redundant
    //[self extractSigningInfo:process forOriginProcess:false];
}

-(void)extractOriginProcessDataForEvent:(es_process_t *)process
{
    NSString *binarypath = convertStringToken(&process->executable->path);
    NSNumber *pid = [NSNumber numberWithInt:audit_token_to_pid(process->audit_token)];
    NSNumber *uid = [NSNumber numberWithInt:audit_token_to_euid(process->audit_token)];
    NSNumber *ppid = [NSNumber numberWithInt:process->ppid];
    
    [self.metadata setValue:binarypath forKey:@"origin_binarypath"];
    [self.metadata setValue:pid forKey:@"origin_pid"];
    [self.metadata setValue:uid forKey:@"origin_uid"];
    [self.metadata setValue:ppid forKey:@"origin_ppid"];
    [self extractSigningInfo:process forOriginProcess:true];
}

// Helper function for file events written by Patrick Wardle
//extract source & destination path
// this requires event specific logic
-(void)extractPaths:(es_message_t*)message
{
    //event specific logic
    switch (message->event_type) {
        
        //create
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            
            //set path
            
            [self.metadata setValue:convertStringToken(&message->event.create.destination.existing_file->path) forKey:@"filepath"];
            
            self.uid = [NSNumber numberWithInt:message->event.create.destination.existing_file->stat.st_uid];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.create.destination.existing_file->stat.st_size] forKey:@"filesize"];
            
            break;
            
        //open
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            
            //set path
            [self.metadata setValue:convertStringToken(&message->event.open.file->path) forKey:@"filepath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.open.file->stat.st_size] forKey:@"filesize"];
            
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.open.file->stat.st_uid];
            
            break;
            
        //write
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            
            //set path
            [self.metadata setValue:convertStringToken(&message->event.write.target->path) forKey:@"filepath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.write.target->stat.st_size] forKey:@"filesize"];
            
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.write.target->stat.st_uid];
            
            break;
            
        //close
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            
            //set path
            
            [self.metadata setValue:convertStringToken(&message->event.close.target->path) forKey:@"filepath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.close.target->stat.st_size] forKey:@"filesize"];
            
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.close.target->stat.st_uid];
            
            
            break;
            
        //link
        case ES_EVENT_TYPE_NOTIFY_LINK:
            
            //set (src) path
            [self.metadata setValue:convertStringToken(&message->event.link.source->path) forKey:@"sourcefilepath"];
            
            //set (dest) path
            // combine dest dir + dest file
            [self.metadata setValue:[convertStringToken(&message->event.link.target_dir->path) stringByAppendingPathComponent:convertStringToken(&message->event.link.target_filename)] forKey:@"destinationfilepath"];
            
            break;
            
        //rename
        case ES_EVENT_TYPE_NOTIFY_RENAME:
                
            //set (src) path
            [self.metadata setValue:convertStringToken(&message->event.rename.source->path) forKey:@"sourcefilepath"];
            
            //existing file ('ES_DESTINATION_TYPE_EXISTING_FILE')
            if(ES_DESTINATION_TYPE_EXISTING_FILE == message->event.rename.destination_type)
            {
                //set (dest) file
                [self.metadata setValue:convertStringToken(&message->event.rename.destination.existing_file->path) forKey:@"destinationfilepath"];
            }
            //new path ('ES_DESTINATION_TYPE_NEW_PATH')
            else
            {
                //set (dest) path
                // combine dest dir + dest file
                [self.metadata setValue:[convertStringToken(&message->event.rename.destination.new_path.dir->path) stringByAppendingPathComponent:convertStringToken(&message->event.rename.destination.new_path.filename)] forKey:@"destinationfilepath"];
            }
            
            break;
            
        //unlink
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
                
            //set path
            [self.metadata setValue:convertStringToken(&message->event.unlink.target->path) forKey:@"filepath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.unlink.target->stat.st_size] forKey:@"filesize"];
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.unlink.target->stat.st_uid];
                
            break;
            
        // Data Exchange
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            [self.metadata setValue:convertStringToken(&message->event.exchangedata.file1->path) forKey:@"file1"];
            [self.metadata setValue:convertStringToken(&message->event.exchangedata.file2->path) forKey:@"file2"];
            
            break;
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            [self.metadata setValue:convertStringToken(&message->event.file_provider_update.target_path) forKey:@"target_path"];
            [self.metadata setValue:convertStringToken(&message->event.file_provider_update.source->path) forKey:@"source_path"];
            break;
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            [self.metadata setValue:convertStringToken(&message->event.file_provider_materialize.source->path) forKey:@"source_path"];
            [self.metadata setValue:convertStringToken(&message->event.file_provider_materialize.target->path) forKey:@"target_path"];
            [self extractSigningInfo:message->event.file_provider_materialize.instigator forOriginProcess:false];
        default:
            break;
    }
    
    return;
}

//extract/format signing info Written by Patrick Wardle
-(void)extractSigningInfo:(es_process_t *)process forOriginProcess:(bool)forOriginalProcess
{
    NSString *codeSignKey;
    NSString *signingIDKey;
    NSString *teamIDKey;
    NSString *cdHashKey;
    NSString *platformBinaryKey;
    
    if (forOriginalProcess) {
        codeSignKey = @"origin_codesigningflags";
        signingIDKey = @"origin_signingid";
        teamIDKey = @"origin_teamid";
        cdHashKey = @"origin_cdhash";
        platformBinaryKey = @"origin_platform_binary";
    } else {
        codeSignKey = @"codesigningflags";
        signingIDKey = @"signingid";
        teamIDKey = @"teamid";
        cdHashKey = @"cdhash";
        platformBinaryKey = @"platform_binary";
    }
    
    //cd hash
    NSMutableString* cdHash = nil;
    
    //signing id
    NSString* signingID = nil;
    
    //team id
    NSString* teamID = nil;
    
    //alloc string for hash
    cdHash = [NSMutableString string];
    
    //add flags
    [self parseCodeSignFlags:process->codesigning_flags keyName:codeSignKey];
    
    
    //convert/add signing id
    signingID = convertStringToken(&process->signing_id);
    if(nil != signingID)
    {
        //add
        [self.metadata setValue:signingID forKey:signingIDKey];
    }
    
    //convert/add team id
    teamID = convertStringToken(&process->team_id);
    if(nil != teamID)
    {
        
        [self.metadata setValue:teamID forKey:teamIDKey];
    }
    
    
    [self.metadata setValue:[NSNumber numberWithBool:process->is_platform_binary] forKey:platformBinaryKey];
    
    //format cdhash
    for(uint32_t i = 0; i<CS_CDHASH_LEN; i++)
    {
        //append
        [cdHash appendFormat:@"%X", process->cdhash[i]];
    }
    
    
    [self.metadata setValue:cdHash forKey:cdHashKey];
    
    return;
}

-(void)parseCodeSignFlags:(uint32_t)value keyName:(NSString*)keyName
{
    [self.metadata setValue:[NSMutableArray array] forKey:keyName];
    
    if ((CS_ADHOC & value) == CS_ADHOC) {
        [self.metadata[keyName] addObject:@"CS_ADHOC"];
    }
    
    if ((CS_HARD & value) == CS_HARD) {
        [self.metadata[keyName] addObject:@"CS_HARD"];
    }
    
    if ((CS_KILL & value) == CS_KILL) {
        [self.metadata[keyName] addObject:@"CS_KILL"];
    }
    
    if ((CS_VALID & value) == CS_VALID) {
        [self.metadata[keyName] addObject:@"CS_VALID"];
    }
    
    if ((CS_KILLED & value) == CS_KILLED) {
        [self.metadata[keyName] addObject:@"CS_KILLED"];
    }
    
    if ((CS_SIGNED & value) == CS_SIGNED) {
        [self.metadata[keyName] addObject:@"CS_SIGNED"];
    }
    
    if ((CS_RUNTIME & value) == CS_RUNTIME) {
        [self.metadata[keyName] addObject:@"CS_RUNTIME"];
    }
    
    if ((CS_DEBUGGED & value) == CS_DEBUGGED) {
        [self.metadata[keyName] addObject:@"CS_DEBUGGED"];
    }
    
    if ((CS_DEV_CODE & value) == CS_DEV_CODE) {
        [self.metadata[keyName] addObject:@"CS_DEV_CODE"];
    }
    
    if ((CS_RESTRICT & value) == CS_RESTRICT) {
        [self.metadata[keyName] addObject:@"CS_RESTRICT"];
    }
    
    if ((CS_FORCED_LV & value) == CS_FORCED_LV) {
        [self.metadata[keyName] addObject:@"CS_FORCED_LV"];
    }
    
    if ((CS_INSTALLER & value) == CS_INSTALLER) {
        [self.metadata[keyName] addObject:@"CS_INSTALLER"];
    }
    
    if ((CS_EXECSEG_JIT & value) == CS_EXECSEG_JIT) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_JIT"];
    }
    
    if ((CS_REQUIRE_LV & value) == CS_REQUIRE_LV) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_JIT"];
    }
    
    if ((CS_ALLOWED_MACHO & value) == CS_ALLOWED_MACHO) {
        [self.metadata[keyName] addObject:@"CS_ALLOWED_MACHO"];
    }
    
    if ((CS_ENFORCEMENT & value) == CS_ENFORCEMENT) {
        [self.metadata[keyName] addObject:@"CS_ENFORCEMENT"];
    }
    
    if ((CS_DYLD_PLATFORM & value) == CS_DYLD_PLATFORM) {
        [self.metadata[keyName] addObject:@"CS_DYLD_PLATFORM"];
    }
    
    if ((CS_EXEC_SET_HARD & value) == CS_EXEC_SET_HARD) {
        [self.metadata[keyName] addObject:@"CS_EXEC_SET_HARD"];
    }
    
    if ((CS_PLATFORM_PATH & value) == CS_PLATFORM_PATH) {
        [self.metadata[keyName] addObject:@"CS_PLATFORM_PATH"];
    }
    
    if ((CS_GET_TASK_ALLOW & value) == CS_GET_TASK_ALLOW) {
        [self.metadata[keyName] addObject:@"CS_GET_TASK_ALLOW"];
    }
    
    if ((CS_EXEC_SET_KILL & value) == CS_EXEC_SET_KILL) {
        [self.metadata[keyName] addObject:@"CS_EXEC_SET_KILL"];
    }
    
    if ((CS_EXECSEG_SKIP_LV & value) == CS_EXECSEG_SKIP_LV) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_SKIP_LV"];
    }
    
    if ((CS_INVALID_ALLOWED & value) == CS_INVALID_ALLOWED) {
        [self.metadata[keyName] addObject:@"CS_INVALID_ALLOWED"];
    }
    
    if ((CS_CHECK_EXPIRATION & value) == CS_CHECK_EXPIRATION) {
        [self.metadata[keyName] addObject:@"CS_INVALID_ALLOWED"];
    }
    
    if ((CS_PLATFORM_BINARY & value) == CS_PLATFORM_BINARY) {
        [self.metadata[keyName] addObject:@"CS_PLATFORM_BINARY"];
    }
    
    if ((CS_EXEC_INHERIT_SIP & value) == CS_EXEC_INHERIT_SIP) {
        [self.metadata[keyName] addObject:@"CS_EXEC_INHERIT_SIP"];
    }
    
    if ((CS_EXECSEG_ALLOW_UNSIGNED & value) == CS_EXECSEG_ALLOW_UNSIGNED) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_ALLOW_UNSIGNED"];
    }
    
    if ((CS_EXECSEG_DEBUGGER & value) == CS_EXECSEG_DEBUGGER) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_DEBUGGER"];
    }
    
    if ((CS_ENTITLEMENT_FLAGS & value) == CS_ENTITLEMENT_FLAGS) {
        [self.metadata[keyName] addObject:@"CS_ENTITLEMENT_FLAGS"];
    }
    
    if ((CS_NVRAM_UNRESTRICTED & value) == CS_NVRAM_UNRESTRICTED) {
        [self.metadata[keyName] addObject:@"CS_NVRAM_UNRESTRICTED"];
    }
    
    if ((CS_EXECSEG_MAIN_BINARY & value) == CS_EXECSEG_MAIN_BINARY) {
        [self.metadata[keyName] addObject:@"CS_EXECSEG_MAIN_BINARY"];
    }
}

//extract/format args (Written by Patrick Wardle)
-(void)extractArgs:(es_events_t *)event
{
    //number of args
    uint32_t count = 0;
    
    //argument
    NSString* argument = nil;
    
    //get # of args
    if (@available(macOS 10.15, *)) {
        count = es_exec_arg_count(&event->exec);
    } else {
        // Fallback on earlier versions
    }
    if(0 == count)
    {
        //bail
        goto bail;
    }
    
    //extract all args
    for(uint32_t i = 0; i < count; i++)
    {
        //current arg
        es_string_token_t currentArg = {0};
        
        //extract current arg
        if (@available(macOS 10.15, *)) {
            currentArg = es_exec_arg(&event->exec, i);
        } else {
            // Fallback on earlier versions
        }
        
        //convert argument
        argument = convertStringToken(&currentArg);
        if(nil != argument)
        {
            //TODO: Add the process arguments to the metadata dictionary
            [self.metadata setValue:argument forKey:@"ProcessArgs"];
        }
    }
    
bail:
    
    return;
}

// Helper function to convert NSDate to NSString for json serialization
-(NSString*)nsDateToString
{
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    [dateFormat setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'"];
    [dateFormat setTimeZone:[NSTimeZone timeZoneWithName:@"GMT"]];
    return [dateFormat stringFromDate:self.timestamp];
}

@end

void NSPrint (NSString *str)
{
    NSError *err;
    [str writeToFile: @"/dev/stdout" atomically:NO encoding:NSUTF8StringEncoding error:&err];
}


EventCallbackBlock _Nonnull blockStdOut = ^(SecurityEvent* newEvent)
{
    if (nil != newEvent)
    {
        NSError *error;
        NSMutableDictionary* dataToSend = [[NSMutableDictionary alloc] init];
        [dataToSend setValue:newEvent.type forKey:@"eventtype"];
        [dataToSend setValue:[newEvent nsDateToString] forKey:@"timestamp"];
        [dataToSend setValue:newEvent.pid forKey:@"processid"];
        [dataToSend setValue:newEvent.metadata forKey:@"metadata"];
        
        NSData* jsonData = [NSJSONSerialization dataWithJSONObject:dataToSend options:NSJSONWritingPrettyPrinted error:&error];
        if(nil == jsonData)
        {
            NSPrint([NSString stringWithFormat: @"Error converting event to json: %@", error]);
        }
        else
        {
            NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            handler((char*)[jsonString UTF8String]);
        }
    }
};


void startEventHandler(Callbacks functionCallback)
{
    handler = functionCallback.f;
    
    Inspecter* eventMonitor = [[Inspecter alloc] init];
    
    [eventMonitor start:blockStdOut];
    [[NSRunLoop currentRunLoop] run];
}




