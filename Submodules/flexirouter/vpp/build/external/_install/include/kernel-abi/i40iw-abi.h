#define _STRUCT_i40iw_alloc_ucontext_req struct { \
__u32 reserved32; \
__u8 userspace_ver; \
__u8 reserved8[3]; \
}

#define _STRUCT_i40iw_alloc_ucontext_resp struct { \
__u32 max_pds;		 \
__u32 max_qps;		 \
__u32 wq_size;		 \
__u8 kernel_ver; \
__u8 reserved[3]; \
}

#define _STRUCT_i40iw_alloc_pd_resp struct { \
__u32 pd_id; \
__u8 reserved[4]; \
}

#define _STRUCT_i40iw_create_cq_req struct { \
__aligned_u64 user_cq_buffer; \
__aligned_u64 user_shadow_area; \
}

#define _STRUCT_i40iw_create_qp_req struct { \
__aligned_u64 user_wqe_buffers; \
__aligned_u64 user_compl_ctx; \
 \
 \
__aligned_u64 user_sq_phb;	 \
__aligned_u64 user_rq_phb;	 \
}

#define _STRUCT_i40iw_mem_reg_req struct { \
__u16 reg_type;		 \
__u16 cq_pages; \
__u16 rq_pages; \
__u16 sq_pages; \
}

#define _STRUCT_i40iw_create_cq_resp struct { \
__u32 cq_id; \
__u32 cq_size; \
__u32 mmap_db_index; \
__u32 reserved; \
}

#define _STRUCT_i40iw_create_qp_resp struct { \
__u32 qp_id; \
__u32 actual_sq_size; \
__u32 actual_rq_size; \
__u32 i40iw_drv_opt; \
__u16 push_idx; \
__u8  lsmm; \
__u8  rsvd2; \
}

