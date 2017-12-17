#import "ViewController.h"
#include <stdio.h>
#include <sys/sysctl.h>

#include "async_wake.h"
#include "patchfinder64_11.h"
#include "symbols.h"
#include "jailbreak.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *deviceModelLabel;
@property (weak, nonatomic) IBOutlet UILabel *kernelbaseLabel;
@property (weak, nonatomic) IBOutlet UILabel *kaslrLabel;
@property (weak, nonatomic) IBOutlet UILabel *trustcacheLabel;
@property (weak, nonatomic) IBOutlet UILabel *amficacheLabel;
@property (weak, nonatomic) IBOutlet UILabel *rootvnode;
@property (weak, nonatomic) IBOutlet UIButton *respringButton;

@end

@implementation ViewController


- (void)addGradient {
    
    UIView *view = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.frame.size.width, self.view.frame.size.height)];
    CAGradientLayer *gradient = [CAGradientLayer layer];
    
    gradient.frame = view.bounds;
    
    gradient.colors = @[(id)[UIColor colorWithRed:0 green:0 blue:0 alpha:1.0].CGColor, (id)[UIColor colorWithRed:0.20 green:0.09 blue:0.31 alpha:1.0].CGColor];
    
    [view.layer insertSublayer:gradient atIndex:0];
    [self.view insertSubview:view atIndex:0];
    
}
kern_return_t ret = KERN_SUCCESS;

- (void)viewDidLoad {
    [super viewDidLoad];
    [self addGradient];
    
    size_t len = 0;
    char *model = malloc(len * sizeof(char));
    sysctlbyname("hw.model", NULL, &len, NULL, 0);
    if (len) {
        sysctlbyname("hw.model", model, &len, NULL, 0);
        printf("[INFO]: model internal name: %s\n", model);
    }
    
    [self.deviceModelLabel setText:[NSString stringWithFormat:@"%s", model]];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
    
        ret = go();
        
        dispatch_async(dispatch_get_main_queue(), ^{

            
            extern uint64_t kernel_base;
            extern uint64_t kaslr_slide;

            [self.kernelbaseLabel setText:[NSString stringWithFormat:@"%llx (%llx)", kernel_base, kernel_base - kaslr_slide]];
            [self.kaslrLabel setText:[NSString stringWithFormat:@"slide: %llx", kaslr_slide]];
            
            int rv = init_kernel(kernel_base, NULL);
            
            if(rv == 0) {

                uint64_t trustcache = find_trustcache();
                uint64_t amficache = find_amficache();
                uint64_t rootvnode = find_rootvnode();
                
                [self.trustcacheLabel setText: [[NSString stringWithFormat:@"0x%llx (0x%llx)", trustcache, (uint64_t)(trustcache - kaslr_slide)] uppercaseString]];
                [self.amficacheLabel setText:[[NSString stringWithFormat:@"0x%llx (0x%llx)", amficache, (uint64_t)(amficache - kaslr_slide)] uppercaseString]];
                
                [self.rootvnode setText:[[NSString stringWithFormat:@"0x%llx (0x%llx)", rootvnode, (uint64_t)(rootvnode - kaslr_slide)] uppercaseString]];
                
                if(ret != KERN_SUCCESS) {
                    [self.respringButton setTitle:@"failed" forState:UIControlStateNormal];
                    return;
                    
                }
                
                [self.respringButton setTitle:@"installing Cydia" forState:UIControlStateNormal];
                
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    
                    unpack_bootstrap();
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        
                        
                        [self.respringButton setTitle:@"respringing.." forState:UIControlStateNormal];
                        
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{

                            printf("[INFO]: respringing..\n");
                            pid_t springboard_pid = get_pid_for_name("SpringBoard");
                            kill(springboard_pid, SIGKILL);
                        });
                    });
                    
                });
                
            }
            
        });
    });
    
}


@end
