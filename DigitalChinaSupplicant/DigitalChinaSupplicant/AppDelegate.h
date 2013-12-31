//
//  AppDelegate.h
//  DigitalChinaSupplicant
//
//  Created by 云心逸 on 13-3-5.
//  Copyright (c) 2013年 云心逸. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
{
    NSString *username;
    NSString *password;
    NSString *version;
    NSString *device;
    NSPipe   *pipe;
    
    IBOutlet NSTextView *logTV;
    IBOutlet NSTextField *usernameTF;
    IBOutlet NSSecureTextField *passwordTF;
    IBOutlet NSTextField *versionTF;
    IBOutlet NSTextField *deviceTF;
    
    IBOutlet NSButton *dhcpBTN;
    IBOutlet NSButton *daemonizeBTN;
    IBOutlet NSButton *loginBTN;
    IBOutlet NSButton *logoffBTN;
    IBOutlet NSWindow *window;
    
}

- (IBAction)Login:(id)sender;
- (IBAction)Logoff:(id)sender;


//@property (assign)

@end
