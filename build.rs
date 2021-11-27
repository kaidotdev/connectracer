fn main() {
    libbpf_cargo::SkeletonBuilder::new("src/bpf/connect.bpf.c")
       .generate(&std::path::Path::new("src/bpf/skel.rs"))
       .unwrap();
}
