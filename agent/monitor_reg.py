from bm_runtime.standard import Standard
import bmpy_utils as utils
from bm_runtime.simple_pre import SimplePre
import math
from time import sleep

K=3
ALPHA=10
NUM_KEYS=64
REG_SIZE=32 #bits
PNTR_SIZE=NUM_KEYS/REG_SIZE #In num of registers


class switchPTimer():
    
    def __init__(self, thrift_ip="127.0.0.1",thrift_port=9090,services=[('standard',Standard.Client),('simple_pre',SimplePre.Client)]):
        self.client, mc_client=utils.thrift_connect(thrift_ip,thrift_port,services)
        self.level_epoch_data={}
        self.ptr_reg_name='pointers'
        self.level_reg_name='level_pointer_idx'
        self.init_levels()
        

    def init_levels(self):
        for level in range(K):
            self.level_epoch_data.update({level:{'clock':0,'trigger':math.pow(ALPHA,level+1),'pointer_idx':0}})

    def start_timer(self):
        while(True):
            for level in range(K):
                e=self.level_epoch_data[level]
                if e['clock']==e['trigger']:
                    e['clock']=0
                    curr_pntr_idx=e['pointer_idx']
                    nxt_pntr_idx=(curr_pntr_idx+1)%ALPHA
                    start_reg_idx=((level*ALPHA)+nxt_pntr_idx)*PNTR_SIZE
                    end_reg_idx=start_reg_idx+PNTR_SIZE-1
                    #print 'level',level,'start',start_reg_idx,'end',end_reg_idx
                    self.reset_reg_range(self.ptr_reg_name,start_reg_idx,end_reg_idx)
                    e['pointer_idx']=nxt_pntr_idx
                    self.write_reg_idx(self.level_reg_name, level,nxt_pntr_idx)
                    start_reg_idx=((level*ALPHA)+curr_pntr_idx)*PNTR_SIZE
                    end_reg_idx=start_reg_idx+PNTR_SIZE-1
                    if level==K-1:
                        print 'level',level,'start',start_reg_idx,'end',end_reg_idx
                        print 'val',self.read_reg_range(self.ptr_reg_name,start_reg_idx,end_reg_idx)
                e['clock'] += ALPHA
            sleep(ALPHA/1000.0)

    def read_reg_idx(self,reg_name,idx):
        return self.client.bm_register_read(0, reg_name, idx)

    def read_reg_idx_all(self, reg_name):
        return self.client.bm_register_read_all(0, reg_name)
    
    def write_reg_idx(self, reg_name,idx,val):
        return self.client.bm_register_write(0, reg_name, idx, val)

    def read_reg_range(self, reg_name,start_idx,end_idx):
        return [self.client.bm_register_read(0,reg_name, x) for x in range(start_idx,end_idx+1)]
    
    def write_reg_range(self, reg_name,start_idx,end_idx,val):
        for x in range(start_idx,end_idx+1):
            self.client.bm_register_write(0, reg_name, x, val)

    def reset_reg_idx(self, reg_name, idx):
        self.client_bm_register_write(0, reg_name, idx, 0)
    
    def reset_reg_range(self, reg_name,start_idx,end_idx):
        for x in range(start_idx,end_idx+1):
            self.client.bm_register_write(0, reg_name, x, 0)


def main():
    cli=switchPTimer()
    cli.start_timer()
    #print cli.read_reg_idx('pointers',60)

if __name__ == '__main__':
    main()
            
