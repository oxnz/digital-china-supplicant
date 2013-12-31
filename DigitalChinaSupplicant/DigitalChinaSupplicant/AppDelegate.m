//
//  AppDelegate.m
//  DigitalChinaSupplicant
//
//  Created by 云心逸 on 13-3-5.
//  Copyright (c) 2013年 云心逸. All rights reserved.
//

#import "AppDelegate.h"

@implementation AppDelegate

- (void)dealloc
{
    if (pipe)
        [pipe release];
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    if ((username = [userDefaults stringForKey:@"username"]) != Nil) {
        [usernameTF setStringValue:username];
    }
    if ((password = [userDefaults stringForKey:@"password"]) != Nil) {
        [passwordTF setStringValue:password];
    }
    if ((version = [userDefaults stringForKey:@"version"]) != Nil) {
        [versionTF setStringValue:version];
    }
    if ((device = [userDefaults stringForKey:@"device"]) != Nil) {
        [deviceTF setStringValue:device];
    }

    const char *bannerHtml = "<html><meta http-equiv=Content-Type content=text/html; charset=UTF8>"
    "<h1 align=center>神州数码客户端</h1>"
    "意见反馈: <a href=mailto:yunxinyi@gmail.com>yunxinyi@gmail.com</a><br />"
    "项目主页: <a href=https://github.com/oxnz/digital-china-supplicant>https://github.com/oxnz/digital-china-supplicant</a>"
    "</html>";
    NSAttributedString *banner = [[NSAttributedString alloc] initWithHTML:[NSData dataWithBytes:bannerHtml length:strlen(bannerHtml)] documentAttributes:NULL];
    //[logTV setAlignment:NSCenterTextAlignment];
    [logTV insertText:banner];
    [logTV insertParagraphSeparator:NULL];
    [logTV setAlignment:NSCenterTextAlignment range:NSMakeRange(0, 7)];
    [banner release];
    
    [daemonizeBTN setEnabled:FALSE];
    [dhcpBTN setEnabled:FALSE];
}

- (int) repairClient{
    [logTV insertText:@"repairing client ...\n"];
    AuthorizationRef auth = NULL;
    OSStatus err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed, &auth);
    if (err != errAuthorizationSuccess) {
        [logTV insertText:@"create repair authorization failed\n"];
        return -1;        
    }
    NSString *repairPath = [[NSBundle mainBundle] pathForResource:@"repairClient" ofType:@".sh"];
    NSString *clientPath = [[NSBundle mainBundle] pathForResource:@"dcclient" ofType:nil];
    char *args[] = {(char *)[clientPath UTF8String], NULL};
    err = AuthorizationExecuteWithPrivileges(auth, [repairPath UTF8String], kAuthorizationFlagDefaults, args, NULL);
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
    if (err != errAuthorizationSuccess) {
        [logTV insertText:@"authorization failed to repair client\n"];
        return -2;
    }
    return 0;
}

- (int)ExecClientWithArgs: (NSArray *)args {
    NSString *clientPath = @"/usr/local/bin/dcclient";
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:clientPath] == NO) {
        [logTV insertText:@"Warning: /usr/bin/local/dcclient is missing\n"];
        NSInteger repairClient = NSRunAlertPanel(
                                                 @"DigitalChinaSupplicant",
                                                 @"the binary client is missing, do you want to repair it?",
                                                 @"Repair", @"Cancel", nil);
        if (repairClient) {
            if ([self repairClient] == 0)
                [logTV insertText:@"repair success!\n"];
            else
                [logTV insertText:@"repair failed!\n"];
            return 1;
        }
        else {
            [logTV insertText:@"Error: no client found, please repair it before login\n"];
            return -1;
        }
    }
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:clientPath];
    [task setArguments:args];
    
    pipe = [[NSPipe alloc] init];
    [task setStandardOutput:pipe];
    [task setStandardError:pipe];
    
    [[NSNotificationCenter defaultCenter]
     addObserver:self
     selector:@selector(dataReady:)
     name:NSFileHandleReadCompletionNotification
     object:[pipe fileHandleForReading]];
    
     [[NSNotificationCenter defaultCenter]
      addObserver:self
      selector:@selector(taskTerminated:)
      name:NSTaskDidTerminateNotification
      object:task];
    
    [task launch];
  
    [[pipe fileHandleForReading] readInBackgroundAndNotify];
    return 0;
}

- (void)dataReady: (NSNotification *) notification {
    NSData *data = [[notification userInfo] valueForKey: NSFileHandleNotificationDataItem];
    if ([data length] != 0) {
        NSString *msg = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (msg != nil && [msg length] != 0) {
            [logTV insertText:msg];
            [msg release];
        }
    }
    [[pipe fileHandleForReading] readInBackgroundAndNotify];
}

- (void) taskTerminated: (NSNotification *)notification {
    NSData *leftInPipe = [[pipe fileHandleForReading] readDataToEndOfFile];
    
    if ([leftInPipe length] != 0) {
        NSString *msg = [[NSString alloc] initWithData:leftInPipe encoding:NSUTF8StringEncoding];
        if (msg != nil && [msg length] != 0) {
            [logTV insertText:msg];
            [msg release];
        }
    }
}

- (IBAction)Login:(id)sender {
    if ([[usernameTF stringValue] length] == 0) {
        [logTV insertText:@"Error: Username can't be NULL\n"];
    }
    else if ([[passwordTF stringValue] length] == 0) {
        [logTV insertText:@"Error: Password can't be NULL\n"];
        NSLog(@"Error: Password can't be NULL");
    }
    else {
        if ([[versionTF stringValue] length] == 0) {
            [versionTF setStringValue:@"3.5.04.1013fk"];
            [logTV insertText:@"Warning: No version supplied, use default version: 3.5.04.1013fk\n"];
        }
        if ([[deviceTF stringValue] length] == 0) {
            [deviceTF setStringValue:@"en0"];
            [logTV insertText:@"Warning: No ether interface supplied, use default: en0\n"];
        }
        NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
        username = [usernameTF stringValue];
        [userDefaults setValue:username forKey:@"username"];
        password = [passwordTF stringValue];
        [userDefaults setValue:password forKey:@"password"];
        version = [versionTF stringValue];
        [userDefaults setValue:version forKey:@"version"];
        device = [deviceTF stringValue];
        [userDefaults setValue:device forKey:@"device"];
        [userDefaults setInteger:[daemonizeBTN state] forKey:@"daemonize"];
        [userDefaults setInteger:[dhcpBTN state] forKey:@"DHCP"];
        [userDefaults synchronize];
        NSArray *args = [NSArray arrayWithObjects:
                         @"-u", username, @"-p", password,
                         @"--ver", version, @"--device", device, @"-b", @"--dhcp", nil];
        [logTV insertText:@"开始认证 ...\n"];
        [self ExecClientWithArgs:args];
    }
}

- (IBAction)Logoff:(id)sender {
    NSArray *args = [NSArray arrayWithObject:@"-l"];
    [logTV insertText:@"断开连接 ...\n"];
    [self ExecClientWithArgs: args];
}

- (BOOL) applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    if (flag) {
        return NO;
    }
    [self->window makeKeyAndOrderFront:nil];
    return YES;
}

@end
