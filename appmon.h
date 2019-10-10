//
//  appmon.h
//  appmon
//
//  Created by Chris Ross on 9/26/19.
//  Copyright © 2019 specterops. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <IOKit/kext/KextManager.h>
#import <Kernel/kern/cs_blobs.h> // For signing flags

// Majority of the code in appmon.h and appmon.m was taken from the ProcessMonitor project by Patrick Wardle
// https://github.com/objective-see/ProcessMonitor
//code signing keys
#define KEY_SIGNATURE_CDHASH @"cdHash"
#define KEY_SIGNATURE_FLAGS @"csFlags"
#define KEY_SIGNATURE_IDENTIFIER @"signatureIdentifier"
#define KEY_SIGNATURE_TEAM_IDENTIFIER @"teamIdentifier"
#define KEY_SIGNATURE_PLATFORM_BINARY @"isPlatformBinary"

// Event Class for events
@class SecurityEvent;

// Typedef for event handling callback function
typedef void (^EventCallbackBlock)(SecurityEvent* _Nonnull);

@interface Inspecter : NSObject
-(BOOL)start:(EventCallbackBlock _Nonnull)callback;
-(BOOL)stop;
@end

@interface SecurityEvent : NSObject

// Properties. These properties will need to be serialized into JSON
@property NSNumber* _Nonnull pid;
@property NSDate* _Nonnull timestamp;
@property NSString* _Nonnull hostname;
@property NSNumber* _Nonnull uid;
@property NSString* _Nonnull user;
@property NSString* _Nonnull type;
@property NSMutableDictionary* _Nonnull metadata;
@property NSPredicate* _Nullable eventFilter;

// Initialization method for all events
-(id _Nullable)init:(es_message_t* _Nonnull)message;
// helper function written by Patrick Wardle to extract arguments for process events
-(void)extractArgs:(es_events_t *_Nonnull)event;
// helper function written by Patrick Wardle to extract signing info in Process events
-(void)extractSigningInfo:(es_process_t *_Nonnull)process forOriginProcess:(bool)forOriginProcess;
// helper function written by Patrick Wardle to extract file path information for file events
-(void)extractPaths:(es_message_t*_Nonnull)message;

// helper function to handle process events in general
-(void)handleProcessEventData:(es_process_t *_Nonnull)process;
-(void)extractOriginProcessDataForEvent:(es_process_t *_Nonnull)process;
-(void)handleGetTaskEventData:(es_event_get_task_t *_Nonnull)task;
-(void)handleMProtectEventData:(es_event_mprotect_t *_Nonnull)mprotect;
-(void)handleMMapEventData:(es_event_mmap_t *_Nonnull)mmap;
-(void)handleKextEventData:(es_message_t *_Nonnull)kext;
-(void)handleSetExtattrEventData:(es_event_setextattr_t *_Nonnull)extattr;
-(void)handleSetAttrlistEventData:(es_event_setattrlist_t *_Nonnull)attr;
-(void)handleSetOwnerEventData:(es_event_setowner_t *_Nonnull)owner;

-(NSString*_Nonnull)nsDateToString;


@end


//helper function
// get parent of arbitrary process
pid_t getParentID(pid_t child);

typedef void (*EventHandlerFn)(char * _Nonnull jsonEventString);
typedef struct {
    EventHandlerFn _Nonnull f;
} Callbacks;
void startEventHandler(Callbacks functionCallback);



