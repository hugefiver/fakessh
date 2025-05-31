{
  description = "Nix flake for hugefiver/fakessh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        inherit (pkgs) lib stdenv fetchFromGitHub fetchurl buildGoModule;

        pkgs = nixpkgs.legacyPackages.${system};

        goVersion = pkgs.go_1_24;
        pkgMetadata = pkgs.lib.importJSON ./nix-metadata.json;
      in {
        packages = import ./default.nix {
          inherit lib stdenv fetchFromGitHub fetchurl buildGoModule pkgMetadata;
          go = goVersion;
        };

        apps.fakessh = {
          type = "app";
          program = "${self.packages.${system}.fakessh}/bin/fakessh";
          meta = self.packages.${system}.fakessh.meta;
        };

        # apps.fakessh-bin = {
        #   type = "app";
        #   program = "${self.packages.${system}.fakessh-bin}/bin/fakessh";
        #   meta = self.packages.${system}.fakessh.meta;
        # };

        devShells.default =
          pkgs.mkShell { packages = with pkgs; [ goVersion git ]; };
      });
}
