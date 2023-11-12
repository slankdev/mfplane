package ebpf

// +ebpf:map:name=lb_backend
// +ebpf:map:render=LbBackendRender
// +ebpf:map:render:key=StructArrayKey32Render
// +ebpf:map:render:val=StructFlowProcessorRender
// +ebpf:map:raw:key=StructArrayKey32
// +ebpf:map:raw:val=StructFlowProcessor
// +ebpf:map:type=BPF_MAP_TYPE_PERCPU_HASH

type LbBackendRenderItem struct {
	Key StructArrayKey32Render    `json:"key"`
	Val StructFlowProcessorRender `json:"val"`
}

type LbBackendRender struct {
	Items []LbBackendRenderItem `json:"items"`
}

// +ebpf:map:name=fib4
// +ebpf:map:render=Fib4Render
// +ebpf:map:render:key=StructTrie4KeyRender
// +ebpf:map:render:val=StructTrie4ValRender
// +ebpf:map:raw:key=StructTrie4Key
// +ebpf:map:raw:val=StructTrie4Val
// +ebpf:map:type=BPF_MAP_TYPE_LPM_TRIE

type Fib4RenderItem struct {
	Key StructTrie4KeyRender `json:"key"`
	Val StructTrie4ValRender `json:"val"`
}

type Fib4Render struct {
	Items []Fib4RenderItem `json:"items"`
}

// +ebpf:map:name=fib6
// +ebpf:map:render=Fib6Render
// +ebpf:map:render:key=StructTrie6KeyRender
// +ebpf:map:render:val=StructTrie6ValRender
// +ebpf:map:raw:key=StructTrie6Key
// +ebpf:map:raw:val=StructTrie6Val
// +ebpf:map:type=BPF_MAP_TYPE_LPM_TRIE

type Fib6RenderItem struct {
	Key StructTrie6KeyRender `json:"key"`
	Val StructTrie6ValRender `json:"val"`
}

type Fib6Render struct {
	Items []Fib6RenderItem `json:"items"`
}

// +ebpf:map:name=nat_out
// +ebpf:map:render=NatOutRender
// +ebpf:map:render:key=StructAddrPortRender
// +ebpf:map:render:val=StructAddrPortStatsRender
// +ebpf:map:raw:key=StructAddrPort
// +ebpf:map:raw:val=StructAddrPortStats
// +ebpf:map:type=BPF_MAP_TYPE_LRU_HASH

type NatOutRenderItem struct {
	Key StructAddrPortRender      `json:"key"`
	Val StructAddrPortStatsRender `json:"val"`
}

type NatOutRender struct {
	Items []NatOutRenderItem `json:"items"`
}

// +ebpf:map:name=nat_ret
// +ebpf:map:render=NatRetRender
// +ebpf:map:render:key=StructAddrPortRender
// +ebpf:map:render:val=StructAddrPortStatsRender
// +ebpf:map:raw:key=StructAddrPort
// +ebpf:map:raw:val=StructAddrPortStats
// +ebpf:map:type=BPF_MAP_TYPE_LRU_HASH

type NatRetRenderItem struct {
	Key StructAddrPortRender      `json:"key"`
	Val StructAddrPortStatsRender `json:"val"`
}

type NatRetRender struct {
	Items []NatRetRenderItem `json:"items"`
}

// +ebpf:map:name=encap_source
// +ebpf:map:render=EncapSourceRender
// +ebpf:map:render:key=StructArrayKey32Render
// +ebpf:map:render:val=StructEncapSourceRender
// +ebpf:map:raw:key=StructArrayKey32
// +ebpf:map:raw:val=StructEncapSource
// +ebpf:map:type=BPF_MAP_TYPE_PERCPU_ARRAY

type EncapSourceRenderItem struct {
	Key StructArrayKey32Render  `json:"key"`
	Val StructEncapSourceRender `json:"val"`
}

type EncapSourceRender struct {
	Items []EncapSourceRenderItem `json:"items"`
}

// +ebpf:map:name=overlay_fib4
// +ebpf:map:render=OverlayFib4Render
// +ebpf:map:render:key=StructOverlayFib4KeyRender
// +ebpf:map:render:val=StructOverlayFib4ValRender
// +ebpf:map:raw:key=StructOverlayFib4Key
// +ebpf:map:raw:val=StructOverlayFib4Val
// +ebpf:map:type=BPF_MAP_TYPE_PERCPU_HASH

type OverlayFib4RenderItem struct {
	Key StructOverlayFib4KeyRender `json:"key"`
	Val StructOverlayFib4ValRender `json:"val"`
}

type OverlayFib4Render struct {
	Items []OverlayFib4RenderItem `json:"items"`
}
