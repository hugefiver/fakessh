{
  lib,
  buildGoModule,
  fetchFromGitHub,
  go,
}:

let
  pkgMetadata = lib.importJSON ./nix-metadata.json;
  inherit (pkgMetadata) version commitId srcHash vendorHash;
in

buildGoModule {
  pname = "fakessh";
  inherit version;

  src = fetchFromGitHub {
    owner = "hugefiver";
    repo = "fakessh";
    rev = version;
    hash = srcHash;
  };

  inherit vendorHash;

  subPackages = [ "." ];

  ldflags = [
    "-s"
    "-w"
    "-X=main.version=${version}"
    "-X=main.goversion=${go.version}"
    "-X=main.commitId=${commitId}"
  ];

  meta = {
    description = "Fake SSH Server | 一个假的 SSH Server";
    homepage = "https://github.com/hugefiver/fakessh";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ hugefiver ];
    mainProgram = "fakessh";
  };
}
