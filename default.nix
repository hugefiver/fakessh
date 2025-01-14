{
  lib,
  go,
  buildGoModule,
  fetchFromGitHub,
}:
buildGoModule rec {
  pname = "fakessh";
  version = "0.5.1";
  commitId = "19b59ef";

  src = fetchFromGitHub {
    owner = "hugefiver";
    repo = "fakessh";
    rev = "v${version}";
    hash = "sha256-3zCuRuu1HWRotOjPZNqhmBneObmCuVgdTvphS5Fn4nU=";
  };

  vendorHash = "sha256-pgW9WNPvyANFTPTJYDd83zZnx23y9LqYZ3ZYk+BzVHI=";

  ldflags = [
    "-s"
    "-w"
    "-X=main.version=${version}"
    "-X=main.goversion=${go.version}"
    # "-X=main.buildTime=${envBuildTime}"
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
