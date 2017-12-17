//
//  utilities.m
//  topanga
//
//  Created by Abraham Masri on 12/16/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#include <dirent.h>
#include <objc/runtime.h>

#include "jailbreak.h"

#import <Foundation/Foundation.h>

@interface LSApplicationWorkspace : NSObject
+ (id) defaultWorkspace;
- (BOOL) registerApplication:(id)application;
- (BOOL) unregisterApplication:(id)application;
- (BOOL) invalidateIconCache:(id)bundle;
- (BOOL) registerApplicationDictionary:(id)application;
- (BOOL) installApplication:(id)application withOptions:(id)options;
- (BOOL) _LSPrivateRebuildApplicationDatabasesForSystemApps:(BOOL)system internal:(BOOL)internal user:(BOOL)user;
@end

Class lsApplicationWorkspace = NULL;
LSApplicationWorkspace* workspace = NULL;

void uicache(void) {
    
    if(lsApplicationWorkspace == NULL || workspace == NULL) {
        lsApplicationWorkspace = (objc_getClass("LSApplicationWorkspace"));
        workspace = [lsApplicationWorkspace performSelector:@selector(defaultWorkspace)];
    }
    
    if ([workspace respondsToSelector:@selector(invalidateIconCache:)]) {
        [workspace invalidateIconCache:nil];
    }
    
    
}
