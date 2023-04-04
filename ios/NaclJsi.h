#import <React/RCTBridgeModule.h>

#import "react-native-nacl-jsi.h"
#import "sodium_18.h"

@interface NaclJsi : NSObject <RCTBridgeModule>
@property (nonatomic, assign) BOOL setBridgeOnMainQueue;
@end
