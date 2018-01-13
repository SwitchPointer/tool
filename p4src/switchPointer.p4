/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define ALPHA 10
#define K 3
#define NO_BUCKETS 16
#define NO_KEYS 64
#define REG_BITS 32
#define LOG_REG_BITS 5
#define POINTER_SIZE NO_KEYS>>LOG_REG_BITS
#define NO_32BIT_REGS (K * ALPHA * POINTER_SIZE)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct metadata {
    bit<32> fch_id;
}
typedef bit <32> reg_t;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    reg_t num_parms=6;
    reg_t base_idx=0;
    reg_t m_idx=1;
    reg_t b_idx=2;
    reg_t p1_idx=3;
    reg_t p2_idx=4;
    reg_t seed1_idx=5;
    reg_t seed2_idx=6;

    register<reg_t>(NO_BUCKETS) g_reg;
    register<reg_t>(NO_32BIT_REGS) pointers;
    register<reg_t>(K) level_pointer_idx;
    register<reg_t>(7) fch_reg; 
    register<reg_t>(2) debug_reg;
    
    action drop() {
        mark_to_drop();
    }

    action set_nhop(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action set_switchp_pointer(reg_t level,reg_t pointer_reg, reg_t pointer_reg_bit){
        
        reg_t pointer_idx;
        reg_t pointer_base;
        reg_t pointer_reg_idx;
        reg_t pointer_val;
        reg_t tmp_val=1;
        
        level_pointer_idx.read(pointer_idx,level); 
        pointer_base=(level*ALPHA)+pointer_idx;
        pointer_reg_idx=(pointer_base * POINTER_SIZE) + pointer_reg;
        pointers.read(pointer_val,pointer_reg_idx);
        pointer_val = pointer_val | (tmp_val << (bit<8>)pointer_reg_bit);
        pointers.write(pointer_reg_idx, pointer_val);
        
    }
    
    action set_switchp(in bit<32> dstAddr) {
        bit<32> res;
        bit<32> g_h1;
        reg_t base;
        reg_t m;
        reg_t b;
        reg_t p1;
        reg_t p2;
        reg_t seed1;
        reg_t seed2;
        reg_t h1;
        reg_t h2;

        fch_reg.read(base,base_idx);
        fch_reg.read(m,m_idx);
        fch_reg.read(b,b_idx);
        fch_reg.read(p1,p1_idx);
        fch_reg.read(p2,p2_idx);
        fch_reg.read(seed1,seed1_idx);
        fch_reg.read(seed2,seed2_idx);
        
        hash(h1,
	    HashAlgorithm.jenkins_hash32,
	    base,
	    { seed1,
	      dstAddr
            },
	    m);
        
        hash(h2,
	    HashAlgorithm.jenkins_hash32,
	    base,
	    { seed2,
	      dstAddr
            },
	    m);
        
        /* mixh10h11h12 */
        if(h1 < p1){
            h1 = h1 & (p2-1);
        } else {
            h1 = h1 & (b-1);
            if (h1 < p2){
                h1 = h1 + p2;    
            }
        }
        g_reg.read(g_h1, h1);    
        res = (h2+g_h1) & (m-1);
        meta.fch_id = res;
        debug_reg.write(0,res);
     
        reg_t pointer_reg;
        reg_t pointer_reg_bit;
        reg_t level;

        pointer_reg = res >> LOG_REG_BITS;
        pointer_reg_bit = res & (REG_BITS-1);
        
        level=0;
        set_switchp_pointer(level,pointer_reg,pointer_reg_bit);
        level=1;
        set_switchp_pointer(level,pointer_reg,pointer_reg_bit);
        level=2;
        set_switchp_pointer(level,pointer_reg,pointer_reg_bit);
    }
   
     
    table switchp_nhop {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            //update_switchp.apply();
            set_switchp(hdr.ipv4.dstAddr);
            switchp_nhop.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
