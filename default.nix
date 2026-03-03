{
  lib,
  buildGoModule,
  go,
  pname ? "fakessh",
  src ? lib.cleanSource ./.,
  version ? "unstable",
  commitId ? "local",
  buildTime ? "unknown",
  vendorHash ? (lib.importJSON ./nix/vendor-hash.json).vendorHash,
}:

buildGoModule {
  inherit pname version src vendorHash;

  subPackages = [ "." ];

  ldflags = [
    "-s"
    "-w"
    "-X=main.version=${version}"
    "-X=main.goversion=${go.version}"
    "-X=main.commitId=${commitId}"
    "-X=main.buildTime=${buildTime}"
  ];

  meta = {
    description = "Fake SSH Server | 一个假的 SSH Server";
    homepage = "https://github.com/hugefiver/fakessh";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ hugefiver ];
    mainProgram = "fakessh";
  };
}
