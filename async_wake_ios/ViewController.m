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

- (void)viewDidLoad {
  [super viewDidLoad];

    size_t len = 0;
    char *model = malloc(len * sizeof(char));
    sysctlbyname("hw.model", NULL, &len, NULL, 0);
    if (len) {
        sysctlbyname("hw.model", model, &len, NULL, 0);
        printf("[INFO]: model internal name: %s\n", model);
    }
    
    [self.deviceModelLabel setText:[NSString stringWithFormat:@"%s", model]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
    
        go();
        
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
                [self.respringButton setTitle:@"installing Cydia" forState:UIControlStateNormal];
                
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
                    
                    unpack_bootstrap();
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        
                        
                        [self.respringButton setTitle:@"respringing.." forState:UIControlStateNormal];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                            pid_t pid;
                            posix_spawn(&pid, "killall", NULL, NULL, (char **)&(const char*[]){ "killall", "SpringBoard", NULL }, NULL);
                            
                        });
                    });
                    
                });
                
            }
            
        });
    });
    
}

- (IBAction)respringTapped:(id)sender {
    
    
}


@end
