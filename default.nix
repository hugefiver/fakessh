{ lib, stdenv, buildGoModule, fetchFromGitHub, fetchurl, pkgMetadata, go }:

let
  inherit (pkgMetadata) version commitId srcHash vendorHash releaseAssets;
  getReleaseAssetForSystem = system:
    lib.findFirst (asset:
      let
        nixOs = if stdenv.isLinux then
          "linux"
        else if stdenv.isDarwin then
          "darwin"
          # else if stdenv.isWindows
          # then "windows"
        else
          null;

        nixArch = if stdenv.hostPlatform.isx86_64 then
          "amd64" # x86_64 -> amd64
        else if stdenv.hostPlatform.isAarch64 then
          "arm64" # aarch64 -> arm64
        else
          null;

        matchesOs = nixOs != null && lib.stringContains asset.name nixOs;
        matchesArch = nixArch != null && lib.stringContains asset.name nixArch;
      in matchesOs && matchesArch) null releaseAssets;

  finalSelectedReleaseAsset = getReleaseAssetForSystem stdenv.system;

  meta = {
    description = "Fake SSH Server | 一个假的 SSH Server";
    homepage = "https://github.com/hugefiver/fakessh";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ hugefiver ];
    mainProgram = "fakessh";
  };
in rec {

  default = fakessh;

  fakessh = buildGoModule {
    pname = "fakessh";
    inherit version meta;

    src = fetchFromGitHub {
      owner = "hugefiver";
      repo = "fakessh";
      rev = "${version}";
      sha256 = srcHash;
    };

    vendorHash = vendorHash;

    subPackages = [ "." ];

    ldflags = [
      "-s"
      "-w"
      "-X=main.version=${version}"
      "-X=main.goversion=${go.version}"
      "-X=main.commitId=${commitId}"
    ];

  };

  # fakessh-bin = stdenv.mkDerivation {
  #   pname = "fakessh-bin";
  #   inherit version meta;

  #   src =
  #     if finalSelectedReleaseAsset != null
  #     then
  #       fetchurl {
  #         url = finalSelectedReleaseAsset.url;
  #         sha256 = finalSelectedReleaseAsset.sha256;
  #       }
  #     else
  #       throw ''
  #         No suitable release asset found for system ${stdenv.system} in nix-metadata.json. 
  #         Please ensure the asset exists and the naming convention is handled in getReleaseAssetForSystem function.'';

  #   installPhase = ''
  #     mkdir -p $out/bin
  #     mv $src/fakessh $out/bin/fakessh
  #     chmod +x $out/bin/fakessh
  #   '';
  # };
}
