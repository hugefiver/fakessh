{
  description = "Nix flake for hugefiver/fakessh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        goVersion = pkgs.go_1_24;

        nixMetadata = pkgs.lib.importJSON ./nix-metadata.json;

        projectVersion = nixMetadata.version;
        commitId = nixMetadata.commitId;
        srcHash = nixMetadata.srcHash;
        vendorHash = nixMetadata.vendorHash;
        releaseAssets = nixMetadata.releaseAssets;

        getReleaseAssetForSystem = system:
          pkgs.lib.findFirst (
            asset: let
              nixOs =
                if pkgs.stdenv.isLinux
                then "linux"
                else if pkgs.stdenv.isDarwin
                then "darwin"
                else if pkgs.stdenv.isWindows
                then "windows"
                else null;

              nixArch =
                if pkgs.stdenv.hostPlatform.isx86_64
                then "amd64" # x86_64 -> amd64
                else if pkgs.stdenv.hostPlatform.isAarch64
                then "arm64" # aarch64 -> arm64
                else null;

              matchesOs = nixOs != null && pkgs.lib.stringContains asset.name nixOs;
              matchesArch = nixArch != null && pkgs.lib.stringContains asset.name nixArch;
            in
              matchesOs && matchesArch
            # && (pkgs.lib.stringContains asset.name "minimal" || true)
          )
          null
          releaseAssets;

        finalSelectedReleaseAsset = getReleaseAssetForSystem system;
      in rec {
        defaultPackage = packages.fakessh;

        packages.fakessh = pkgs.buildGoModule {
          pname = "fakessh";
          version = projectVersion;

          src = pkgs.fetchFromGitHub {
            owner = "hugefiver";
            repo = "fakessh";
            rev = "${projectVersion}";
            sha256 = srcHash;
          };

          vendorHash = vendorHash;

          # goPackagePath = ".";
          subPackages = ["."];

          # ldflags = [ "-tags=nogitserver,nofakeshell" ];
          ldflags = [
            "-s"
            "-w"
            "-X=main.version=${projectVersion}"
            "-X=main.goversion=${goVersion.version}"
            # "-X=main.buildTime=${envBuildTime}"
            "-X=main.commitId=${commitId}"
          ];

          meta = with pkgs; {
            description = "Fake SSH Server | 一个假的 SSH Server";
            homepage = "https://github.com/hugefiver/fakessh";
            license = lib.licenses.mit;
            maintainers = with lib.maintainers; [hugefiver];
            mainProgram = "fakessh";
          };
        };

        # 从GitHub Release下载二进制文件安装 fakessh
        packages.fakessh-bin = pkgs.stdenv.mkDerivation {
          pname = "fakessh-bin";
          version = projectVersion;

          src =
            if finalSelectedReleaseAsset != null
            then
              pkgs.fetchurl {
                url = finalSelectedReleaseAsset.url;
                sha256 = finalSelectedReleaseAsset.sha256;
              }
            else
              throw ''
                No suitable release asset found for system ${system} in nix-metadata.json. 
                Please ensure the asset exists and the naming convention is handled in getReleaseAssetForSystem function.'';

          installPhase = ''
            mkdir -p $out/bin
            mv $src/fakessh $out/bin/fakessh
            chmod +x $out/bin/fakessh
          '';

          # buildInputs = [ pkgs.glibc ];
        };

        apps.fakessh = {
          type = "app";
          program = "${self.packages.${system}.fakessh}/bin/fakessh";
        };

        apps.fakessh-bin = {
          type = "app";
          program = "${self.packages.${system}.fakessh-bin}/bin/fakessh";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            goVersion
            git
          ];
        };
      }
    );
}
