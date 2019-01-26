extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/skein3fish/skein.c")
        .file("src/skein3fish/skeinApi.c")
        .file("src/skein3fish/skeinBlockNo3F.c")
        .file("src/skein3fish/threefish1024Block.c")
        .file("src/skein3fish/threefish256Block.c")
        .file("src/skein3fish/threefish512Block.c")
        .file("src/skein3fish/threefishApi.c")
        .compile("rsec");
}
