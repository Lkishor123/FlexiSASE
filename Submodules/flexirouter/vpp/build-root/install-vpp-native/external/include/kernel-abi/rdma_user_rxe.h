#define _STRUCT_rxe_gid union { \
__u8	raw[16]; \
struct { \
__be64	subnet_prefix; \
__be64	interface_id; \
} global; \
}

#define _STRUCT_rxe_global_route struct { \
union rxe_gid	dgid; \
__u32		flow_label; \
__u8		sgid_index; \
__u8		hop_limit; \
__u8		traffic_class; \
}

#define _STRUCT_rxe_av struct { \
__u8			port_num; \
__u8			network_type; \
__u8			dmac[6]; \
struct rxe_global_route	grh; \
union { \
struct sockaddr_in	_sockaddr_in; \
struct sockaddr_in6	_sockaddr_in6; \
} sgid_addr, dgid_addr; \
}

#define _STRUCT_rxe_send_wr struct { \
__aligned_u64		wr_id; \
__u32			num_sge; \
__u32			opcode; \
__u32			send_flags; \
union { \
__be32		imm_data; \
__u32		invalidate_rkey; \
} ex; \
union { \
struct { \
__aligned_u64 remote_addr; \
__u32	rkey; \
__u32	reserved; \
} rdma; \
struct { \
__aligned_u64 remote_addr; \
__aligned_u64 compare_add; \
__aligned_u64 swap; \
__u32	rkey; \
__u32	reserved; \
} atomic; \
struct { \
__u32	remote_qpn; \
__u32	remote_qkey; \
__u16	pkey_index; \
} ud; \
 \
struct { \
union { \
struct ib_mr *mr; \
__aligned_u64 reserved; \
}; \
__u32        key; \
__u32        access; \
} reg; \
} wr; \
}

#define _STRUCT_rxe_sge struct { \
__aligned_u64 addr; \
__u32	length; \
__u32	lkey; \
}

#define _STRUCT_mminfo struct { \
__aligned_u64  		offset; \
__u32			size; \
__u32			pad; \
}

#define _STRUCT_rxe_dma_info struct { \
__u32			length; \
__u32			resid; \
__u32			cur_sge; \
__u32			num_sge; \
__u32			sge_offset; \
__u32			reserved; \
union { \
__u8		inline_data[0]; \
struct rxe_sge	sge[0]; \
}; \
}

#define _STRUCT_rxe_send_wqe struct { \
struct rxe_send_wr	wr; \
struct rxe_av		av; \
__u32			status; \
__u32			state; \
__aligned_u64		iova; \
__u32			mask; \
__u32			first_psn; \
__u32			last_psn; \
__u32			ack_length; \
__u32			ssn; \
__u32			has_rd_atomic; \
struct rxe_dma_info	dma; \
}

#define _STRUCT_rxe_recv_wqe struct { \
__aligned_u64		wr_id; \
__u32			num_sge; \
__u32			padding; \
struct rxe_dma_info	dma; \
}

#define _STRUCT_rxe_create_cq_resp struct { \
struct mminfo mi; \
}

#define _STRUCT_rxe_resize_cq_resp struct { \
struct mminfo mi; \
}

#define _STRUCT_rxe_create_qp_resp struct { \
struct mminfo rq_mi; \
struct mminfo sq_mi; \
}

#define _STRUCT_rxe_create_srq_resp struct { \
struct mminfo mi; \
__u32 srq_num; \
__u32 reserved; \
}

#define _STRUCT_rxe_modify_srq_cmd struct { \
__aligned_u64 mmap_info_addr; \
}

